#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list fifo_ready_list;

/* 优先级进程队列 */
/* TODO:使用大顶堆实现，又名优先级队列。 */
static struct list prio_ready_list;

/* List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

/* Idle thread. */
static struct thread* idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread* initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* mlfqs调度时的平均负载 */
fixed_point_t load_avg;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame {
  void* eip;             /* Return address. */
  thread_func* function; /* Function to call. */
  void* aux;             /* Auxiliary data for function. */
};

/* Stack frame for user(). */
struct user_thread_frame {
  void* eip;             /* Return address. */
  stub_fun* function;    /* Function to call. */
  void* aux;             /* Auxiliary data for function. */
};

/* Statistics. */
static long long idle_ticks;   /* # of timer ticks spent idle. */
static long long kernel_ticks; /* # of timer ticks in kernel threads. */
static long long user_ticks;   /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4          /* # of timer ticks to give each thread. */
static unsigned thread_ticks; /* # of timer ticks since last yield. */

static void init_thread(struct thread*, const char* name, int priority);
static bool is_thread(struct thread*) UNUSED;
static void* alloc_frame(struct thread*, size_t size);
static void schedule(void);
static void thread_enqueue(struct thread* t);
static tid_t allocate_tid(void);
void thread_switch_tail(struct thread* prev);

static void kernel_thread(thread_func*, void* aux);
static void idle(void* aux UNUSED);
static struct thread* running_thread(void);

static struct thread* next_thread_to_run(void);
static struct thread* thread_schedule_fifo(void);
static struct thread* thread_schedule_prio(void);
static struct thread* thread_schedule_fair(void);
static struct thread* thread_schedule_mlfqs(void);
static struct thread* thread_schedule_reserved(void);

/* Determines which scheduler the kernel should use.
   Controlled by the kernel command-line options
    "-sched=fifo", "-sched=prio",
    "-sched=fair". "-sched=mlfqs"
   Is equal to SCHED_FIFO by default. */
enum sched_policy active_sched_policy;

/* Selects a thread to run from the ready list according to
   some scheduling policy, and returns a pointer to it. */
typedef struct thread* scheduler_func(void);

/* Jump table for dynamically dispatching the current scheduling
   policy in use by the kernel. */
scheduler_func* scheduler_jump_table[8] = {thread_schedule_fifo,     thread_schedule_prio,
                                           thread_schedule_fair,     thread_schedule_mlfqs,
                                           thread_schedule_reserved, thread_schedule_reserved,
                                           thread_schedule_reserved, thread_schedule_reserved};

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void thread_init(void) {
  ASSERT(intr_get_level() == INTR_OFF);

  lock_init(&tid_lock);
  list_init(&fifo_ready_list);
  list_init(&all_list);
  list_init(&prio_ready_list);

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread();
  init_thread(initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid();
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void thread_start(void) {
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init(&idle_started, 0);
  load_avg = fix_int (0);
  thread_create("idle", PRI_MIN, idle, &idle_started);

  /* Start preemptive thread scheduling. */
  intr_enable();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down(&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void thread_tick(void) {
  struct thread* t = thread_current();

  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pcb != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE)
    intr_yield_on_return();
}

/* Prints thread statistics. */
void thread_print_stats(void) {
  printf("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n", idle_ticks, kernel_ticks,
         user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t thread_create(const char* name, int priority, thread_func* function, void* aux) {
  struct thread* t;
  struct kernel_thread_frame* kf;
  struct switch_entry_frame* ef;
  struct switch_threads_frame* sf;
  tid_t tid;

  ASSERT(function != NULL);

  /* Allocate thread. */
  t = palloc_get_page(PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  init_thread(t, name, priority);
  tid = t->tid = allocate_tid();

  /*保存当前线程作为子线程时的状态 */
  t->child = (struct thread_list_item*)malloc(sizeof(struct thread_list_item));
  t->child->tid = tid;
  t->child->t = t;
  t->child->is_alive = true;
  t->child->exit_code = 0;
  t->child->is_waiting_on = false;
  t->ticks_blocked = 0;
  sema_init(&t->child->wait_sema, 0);

  t->fpu_flag = false;
  t->join_wait_count = 0;
  t->is_join_waited =false;

  t->parent = thread_current();
  // 向父线程添加当前线程为子线程
  list_push_back(&t->parent->child_thread, &t->child->elem);

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame(t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function; // start_process函数
  kf->aux = aux; //运行start_process的参数

  /* Stack frame for switch_entry(). */
  ef = alloc_frame(t, sizeof *ef);
  ef->eip = (void (*)(void))kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame(t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;

  /* Add to run queue. */
  thread_unblock(t);
   if (thread_current ()->priority < priority)
   {
     thread_yield ();
   }

  return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void thread_block(void) {
  ASSERT(!intr_context());
  ASSERT(intr_get_level() == INTR_OFF);

  struct thread *cur = thread_current();

  // 完成浮点运算状态保存再阻塞
  if(cur->fpu_flag == true ) {
    asm volatile("fnsave (%%eax) \n" ::"a"(cur->fpu_state));
    fpu_disable();
    cur->fpu_flag = false;
  }

  cur->status = THREAD_BLOCKED;
  schedule();
}

/* Remove a lock. */
void thread_remove_lock (struct lock *lock)
{
  enum intr_level old_level = intr_disable ();
  list_remove (&lock->elem);
  thread_update_priority(thread_current());
  intr_set_level (old_level);
}

bool thread_cmp_priority(const struct list_elem* a, const struct list_elem* b, void* aux UNUSED){
  return list_entry(a,struct thread,elem)->priority > list_entry(b,struct thread,elem)->priority;
}

/* lock comparation function */
bool lock_cmp_priority (const struct list_elem *a, const struct list_elem *b, void *aux UNUSED)
{
  return list_entry (a, struct lock, elem)->max_priority > list_entry (b, struct lock, elem)->max_priority;
}

/* Let thread hold a lock , insert lock into priority list of lock*/
void thread_hold_the_lock(struct lock *lock)
{
  enum intr_level old_level = intr_disable ();
  list_insert_ordered (&thread_current ()->locks, &lock->elem, lock_cmp_priority, NULL);

  if (lock->max_priority > thread_current ()->priority)
  {
    thread_current ()->priority = lock->max_priority;
    // 被捐赠的低优先级线程的线程被改变需要抢占式调度。
    thread_yield ();
  }

  intr_set_level (old_level);
}

/* Update priority. */
void thread_update_priority(struct thread *t)
{
  enum intr_level old_level = intr_disable ();
  int max_priority = t->base_priority;
  int lock_priority;

  if (!list_empty (&t->locks))
  {
    list_sort (&t->locks, lock_cmp_priority, NULL);
    lock_priority = list_entry (list_front (&t->locks), struct lock, elem)->max_priority;
    if (lock_priority > max_priority)
      max_priority = lock_priority;
  }

  t->priority = max_priority;
  intr_set_level (old_level);
}

/* Donate current priority to thread t. */
void thread_donate_priority(struct thread *t)
{
  enum intr_level old_level = intr_disable ();
  thread_update_priority(t);

  if (t->status == THREAD_READY)
  {
    list_remove(&t->elem);
    list_insert_ordered(&prio_ready_list, &t->elem, thread_cmp_priority, NULL);
  }
  intr_set_level (old_level);
}

/* Places a thread on the ready structure appropriate for the
   current active scheduling policy.
   
   This function must be called with interrupts turned off. */
static void thread_enqueue(struct thread* t) {
  ASSERT(intr_get_level() == INTR_OFF);
  ASSERT(is_thread(t));

  if (active_sched_policy == SCHED_FIFO)
    list_push_back(&fifo_ready_list, &t->elem);
  else if (active_sched_policy == SCHED_PRIO)
    list_insert_ordered(&prio_ready_list, &t->elem, (list_less_func *) &thread_cmp_priority, NULL);
  else
    PANIC("Unimplemented scheduling policy value: %d", active_sched_policy);
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void thread_unblock(struct thread* t) {
  enum intr_level old_level;

  ASSERT(is_thread(t));

  old_level = intr_disable();
  ASSERT(t->status == THREAD_BLOCKED);
  thread_enqueue(t);
  t->status = THREAD_READY;
  intr_set_level(old_level);
}

/* Returns the name of the running thread. */
const char* thread_name(void) { return thread_current()->name; }

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread* thread_current(void) {
  struct thread* t = running_thread();

  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT(is_thread(t));
  ASSERT(t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t thread_tid(void) { return thread_current()->tid; }

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void thread_exit(void) {
  ASSERT(!intr_context());

  struct thread *t_cur = thread_current();
  struct list_elem* e;
  /* 将子线程的parent 置为 NULL */
  for (e = list_begin (&t_cur->child_thread); e != list_end (&t_cur->child_thread); e = list_next (e)) {
    struct thread_list_item *item = list_entry(e, struct thread_list_item, elem);
    // printf("parent-exit\n");
    if(item->is_alive) {
      item->t->parent = NULL;
    }
  }

  //释放所有打开的文件
  while (!list_empty(&t_cur->file_list))
  {
    e = list_pop_front(&t_cur->file_list);
    struct file_opened *item = list_entry(e, struct file_opened, file_elem);
    if(item->file_ptr!=NULL){
      file_close(item->file_ptr);
    }
    free(item);
  }

  // 取消无法写入可执行你文件的保护
  if(t_cur->cur_thread_exec_file!=NULL) {
    file_allow_write(t_cur->cur_thread_exec_file);
  }

#ifdef USERPROG
  process_exit();//释放pagedir
#endif

  /* 将退出的线程为子线程的处理 ,注意这个操作要在process_exit完成后再执行，不然父线程不等子线程完成就执行完成了。*/
  if(t_cur->parent == NULL) {
    free(t_cur->child);
  } else {
    // 保存当前子线程的 退出码，父线程可以访问到child->exit_code。
    t_cur->child->exit_code = t_cur->exit_code;
    /*  */
    if (t_cur->child->is_waiting_on) {
      sema_up(&t_cur->child->wait_sema);
    }
    // // 释放会出错
    // if(t_cur->fpu_state !=NULL){
    //   free(t_cur->fpu_state);
    // }
    // printf("is_alive be false\n");
    
    if (t_cur->is_join_waited) {
      t_cur->parent->join_wait_count -= 1;
      if(t_cur->parent->join_wait_count == 0){
        thread_unblock(t_cur->parent);
      }
    }

    t_cur->child->is_alive = false;
    t_cur->child->t = NULL;
  }

  // 对exit的线程不执行fsave的操作保存浮点运算状态
  t_cur->fpu_flag = false;

  /* Remove thread from all threads list, set our status to dying,
     and schedule another process.  That process will destroy us
     when it calls thread_switch_tail(). */
  intr_disable();
  list_remove(&thread_current()->allelem);
  thread_current()->status = THREAD_DYING;
  schedule();
  NOT_REACHED();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void thread_yield(void) {
  struct thread* cur = thread_current();
  enum intr_level old_level;

  ASSERT(!intr_context());

  old_level = intr_disable();
  if (cur != idle_thread)
    thread_enqueue(cur);
  cur->status = THREAD_READY;
  schedule();
  intr_set_level(old_level);
}

/* Increase recent_cpu by 1. */
void
thread_mlfqs_increase_recent_cpu_by_one (void)
{
  ASSERT (active_sched_policy == SCHED_MLFQS);
  ASSERT (intr_context ());

  struct thread *current_thread = thread_current ();
  if (current_thread == idle_thread)
    return;
  current_thread->recent_cpu = fix_add (current_thread->recent_cpu, fix_int(1));
}

/* Update priority. */
void
thread_mlfqs_update_priority (struct thread *t)
{
  if (t == idle_thread)
    return;

  ASSERT (active_sched_policy == SCHED_MLFQS);
  ASSERT (t != idle_thread);

  t->priority =  fix_round (fix_sub (fix_sub (fix_int(PRI_MAX), fix_div (t->recent_cpu, fix_int(4))), 
    fix_int(2* t->nice)));
  t->priority = t->priority < PRI_MIN ? PRI_MIN : t->priority;
  t->priority = t->priority > PRI_MAX ? PRI_MAX : t->priority;
}

/* Every per second to refresh load_avg and recent_cpu of all threads. */
void
thread_mlfqs_update_load_avg_and_recent_cpu (void)
{
  ASSERT (active_sched_policy == SCHED_MLFQS);
  ASSERT (intr_context ());

  // 优先级就绪队列
  size_t ready_threads = list_size (&prio_ready_list);
  if (thread_current () != idle_thread)
    ready_threads++;
  load_avg = fix_add (
    fix_mul(fix_div(fix_int(59),fix_int(60)),load_avg), 
    fix_mul( fix_inv(fix_int(60)),fix_int(ready_threads))
  );
  struct thread *t;
  struct list_elem *e = list_begin (&all_list);
  for (; e != list_end (&all_list); e = list_next (e))
  {
    t = list_entry(e, struct thread, allelem);
    if (t != idle_thread)
    {
      t->recent_cpu =  fix_add (
        fix_mul (fix_div (
          fix_mul(load_avg, fix_int(2)),
          fix_add (fix_mul(load_avg, fix_int(2)), fix_int(1))
          ), 
          t->recent_cpu), 
        fix_int(t->nice));
      thread_mlfqs_update_priority (t);
    }
  }
}

/* Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void thread_foreach(thread_action_func* func, void* aux) {
  struct list_elem* e;

  ASSERT(intr_get_level() == INTR_OFF);

  for (e = list_begin(&all_list); e != list_end(&all_list); e = list_next(e)) {
    struct thread* t = list_entry(e, struct thread, allelem);
    func(t, aux);
  }
}

void thread_set_priority (int new_priority)
{
  if (active_sched_policy == SCHED_MLFQS){
    return;
  }

  enum intr_level old_level = intr_disable ();

  struct thread *current_thread = thread_current ();
  int old_priority = current_thread->priority;
  current_thread->base_priority = new_priority;

  if (list_empty (&current_thread->locks) || new_priority > old_priority)
  {
    current_thread->priority = new_priority;
    thread_yield ();
  }

  intr_set_level (old_level);
}

/* Returns the current thread's priority. */
int thread_get_priority(void) { return thread_current()->priority; }

/* Sets the current thread's nice value to NICE. */
void thread_set_nice(int nice UNUSED) { /* Not yet implemented. */
  thread_current ()->nice = nice;
  thread_mlfqs_update_priority (thread_current ());
  thread_yield ();
}

/* Returns the current thread's nice value. */
int thread_get_nice(void) {
  /* Not yet implemented. */
  return thread_current ()->nice;
}

/* Returns 100 times the system load average. */
int thread_get_load_avg(void) {
  /* Not yet implemented. */
  return fix_round (fix_mul (load_avg, fix_int(100)));
}

/* Returns 100 times the current thread's recent_cpu value. */
int thread_get_recent_cpu(void) {
  /* Not yet implemented. */
    return fix_round (fix_mul (thread_current ()->recent_cpu, fix_int(100)));
}

/* Check the blocked thread */
void blocked_thread_check (struct thread *t, void *aux UNUSED)
{
  if (t->status == THREAD_BLOCKED && t->ticks_blocked > 0)
  {
      t->ticks_blocked--;
      if (t->ticks_blocked == 0)
      {
          thread_unblock(t);
      }
  }
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void idle(void* idle_started_ UNUSED) {
  struct semaphore* idle_started = idle_started_;
  idle_thread = thread_current();
  sema_up(idle_started);

  for (;;) {
    /* Let someone else run. */
    intr_disable();
    thread_block();

    /* Re-enable interrupts and wait for the next one.

         The `sti' instruction disables interrupts until the
         completion of the next instruction, so these two
         instructions are executed atomically.  This atomicity is
         important; otherwise, an interrupt could be handled
         between re-enabling interrupts and waiting for the next
         one to occur, wasting as much as one clock tick worth of
         time.

         See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
         7.11.1 "HLT Instruction". */
    asm volatile("sti; hlt" : : : "memory");
  }
}

/* Function used as the basis for a kernel thread. */
static void kernel_thread(thread_func* function, void* aux) {
  ASSERT(function != NULL);

  intr_enable(); /* The scheduler runs with interrupts off. */
  function(aux); /* Execute the thread function. */
  thread_exit(); /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread* running_thread(void) {
  uint32_t* esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Because `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm("mov %%esp, %0" : "=g"(esp));
  return pg_round_down(esp);
}

/* Returns true if T appears to point to a valid thread. */
static bool is_thread(struct thread* t) { return t != NULL && t->magic == THREAD_MAGIC; }

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void init_thread(struct thread* t, const char* name, int priority) {
  enum intr_level old_level;

  ASSERT(t != NULL);
  ASSERT(PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT(name != NULL);

  memset(t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy(t->name, name, sizeof t->name);
  t->stack = (uint8_t*)t + PGSIZE;
  t->priority = priority;
  t->pcb = NULL;
  t->fd_can_allocate = 2; // 跳过 0、1
  t->magic = THREAD_MAGIC;

  t->base_priority = priority;
  list_init(&t->locks);
  list_init(&t->join_thread);
  t->lock_waiting = NULL;

  t->nice = 0;
  t->recent_cpu = fix_int(0);

  // 初始化打开的文件的列表
  list_init(&t->file_list);
  list_init(&t->child_thread);
  sema_init(&t->exec_sem, 0);
  t->exec_result = false;

  old_level = intr_disable();
  list_push_back(&all_list, &t->allelem);
  intr_set_level(old_level);
}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void* alloc_frame(struct thread* t, size_t size) {
  /* Stack data is always allocated in word-size units. */
  ASSERT(is_thread(t));
  ASSERT(size % sizeof(uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/* First-in first-out scheduler */
static struct thread* thread_schedule_fifo(void) {
  if (!list_empty(&fifo_ready_list))
    return list_entry(list_pop_front(&fifo_ready_list), struct thread, elem);
  else
    return idle_thread;
}

/* Strict priority scheduler */
static struct thread* thread_schedule_prio(void) {
  if (!list_empty(&prio_ready_list))
    return list_entry(list_pop_front(&prio_ready_list), struct thread, elem);
  else
    return idle_thread;
}

/* Fair priority scheduler */
static struct thread* thread_schedule_fair(void) {
  PANIC("Unimplemented scheduler policy: \"-sched=fair\"");
}

/* Multi-level feedback queue scheduler */
static struct thread* thread_schedule_mlfqs(void) {
  PANIC("Unimplemented scheduler policy: \"-sched=mlfqs\"");
}

/* Not an actual scheduling policy — placeholder for empty
 * slots in the scheduler jump table. */
static struct thread* thread_schedule_reserved(void) {
  PANIC("Invalid scheduler policy value: %d", active_sched_policy);
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread* next_thread_to_run(void) {
  return (scheduler_jump_table[active_sched_policy])();
}

/* Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_switch() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */
void thread_switch_tail(struct thread* prev) {
  struct thread* cur = running_thread();

  ASSERT(intr_get_level() == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;
  
  /* 维护全局当前线程 */ 
  global_thread_current = cur;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  if(prev != NULL)
    process_activate();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread) {
    ASSERT(prev != cur);
    palloc_free_page(prev);
  }
}

/* Schedules a new thread.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.

   It's not safe to call printf() until thread_switch_tail()
   has completed. */
static void schedule(void) {
  struct thread* cur = running_thread();
  struct thread* next = next_thread_to_run();
  struct thread* prev = NULL;

  ASSERT(intr_get_level() == INTR_OFF);
  ASSERT(cur->status != THREAD_RUNNING);
  ASSERT(is_thread(next));

  if (cur != next) {
    if(cur->fpu_flag == true ) {
      asm volatile("fnsave (%%eax) \n" ::"a"(cur->fpu_state));
      cur->fpu_flag = false;
      fpu_disable();
    }
    prev = switch_threads(cur, next);
  }
  thread_switch_tail(prev);
  // printf("cur %s\n",cur->name);
  // printf("next %s\n",next->name);
  // printf("switch\n");
}

/* Returns a tid to use for a new thread. */
static tid_t allocate_tid(void) {
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire(&tid_lock);
  tid = next_tid++;
  lock_release(&tid_lock);

  return tid;
}

/* Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof(struct thread, stack);

enum
{
   CR0_EM = 1 << 2,  // Emulation 启用模拟，表示没有 FPU
   CR0_TS = 1 << 3,  // Task Switch 任务切换，延迟保存浮点环境
};

uint32_t get_cr0()
{
   // 直接将 mov eax, cr0，返回值在 eax 中
   asm volatile("movl %cr0, %eax\n");
};

// 设置 cr0 寄存器，参数是页目录的地址
void set_cr0(uint32_t cr0)
{
   asm volatile("movl %%eax, %%cr0\n" ::"a"(cr0));
}

// 禁用FPU
void fpu_disable()
{
  set_cr0(get_cr0() | (CR0_EM | CR0_TS));
}

void fpu_enable(){
  set_cr0(get_cr0() & ~(CR0_EM | CR0_TS));
}

/*
  用户态系统调用使用的函数
*/



/*
在内核中创建用户态线程的函数
sfun 桩函数，执行入口
fun 线程函数
arg 线程参数
*/
tid_t kernel_pthread_create(stub_fun* sfun,pthread_fun* pfun, uint32_t* arg) {
  struct thread* t;
  struct user_thread_frame* uf;
  struct switch_entry_frame* ef;
  struct switch_threads_frame* sf;
  tid_t tid;

  /* Allocate thread.使用用户态内存空间 */
  t = palloc_get_page(PAL_USER);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  init_thread(t, "default-user-thread", PRI_DEFAULT);
  tid = t->tid = allocate_tid();

  /*保存当前线程作为子线程时的状态 */
  t->child = (struct thread_list_item*)malloc(sizeof(struct thread_list_item));
  t->child->tid = tid;
  t->child->t = t;
  t->child->is_alive = true;
  t->child->exit_code = 0;
  t->child->is_waiting_on = false;
  t->ticks_blocked = 0;
  sema_init(&t->child->wait_sema, 0);

  t->fpu_flag = false;
  t->status = THREAD_BLOCKED;
  t->is_join_waited =false;

  // 获取用户态触发中断的当前运行线程地址。
  t->parent = global_thread_current;
  // 向父线程添加当前线程为子线程
  list_push_back(&t->parent->child_thread, &t->child->elem);

  /* Stack frame for kernel_thread(). */
  uf = alloc_frame(t, sizeof *uf);
  uf->eip = NULL;
  uf->function = pfun;
  uf->aux = *arg;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame(t, sizeof *ef);
  ef->eip = *sfun;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame(t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = (uint8_t*)t+PGSIZE; // 4K用户态空间的顶端

  /* Add to run queue. */
  thread_unblock(t);
  if (thread_current()->priority < PRI_DEFAULT)
  {
    thread_yield();
  }

  return tid;
}