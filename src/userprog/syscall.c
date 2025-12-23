#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"

static void syscall_handler(struct intr_frame*);

static size_t ptr_size = sizeof(void *);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint32_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint32_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

// uaddr类型要指定void，不能是uint32_t
void* check_user_addr_can_read(const void *uaddr,size_t size) {
  if (!is_user_vaddr(uaddr)) {
    process_terminate();
  }
  for(int i=0;i<size;i++) {
    if(get_user(uaddr+i)== -1) {
      process_terminate(); 
    }
  }
  return (void *)uaddr;
}

void* check_user_addr_can_write(const void *uaddr,size_t size) {
  if (!is_user_vaddr(uaddr)) {
    process_terminate();
  }
  for(int i=0;i<size;i++) {
    if(!put_user(uaddr,0)) {
      int exit_code;
      asm volatile ("mov %%eax, %0" : "=g"(exit_code));
      process_terminate(); 
    }
  }
  return (void *)uaddr;
}

void* check_str_can_read(const uint32_t *uaddr)
{
    if (!is_user_vaddr(uaddr)) {
    process_terminate();
  }
  for(int i=0;;i++) {
    if(get_user(uaddr+i) == -1) {
      process_terminate(); 
    } else if(*(char*)(uaddr+i) == '\0') {
      break;
    }
  }
  return (void *)uaddr;
}

/* Reads 4 byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user_4byte (const uint32_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes 4 BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user_4byte (uint32_t *udst, uint32_t data)
{
  int error_code;
  asm ("movl $1f, %0; movl %2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (data));
  return error_code != -1;
}

struct file_opened* get_file(int* fd) {
  struct thread *t_cur = thread_current();
  struct list_elem* i;

  for( i = list_begin(&t_cur->file_list);
    i!=list_end(&t_cur->file_list); i = list_next(i)) {
      struct file_opened* file_opened_ptr = list_entry(i,struct file_opened,file_elem);
      if(file_opened_ptr->fd == fd) {
        return file_opened_ptr;
      }
    }

  return NULL;
} 

/* 中断处理函数 */
void sys_call_halt() {
  shutdown_power_off();
}

void sys_call_create(struct intr_frame* f) {
  const char *flie_name = *(char**)check_user_addr_can_read(f->esp + ptr_size, ptr_size);
  check_str_can_read(flie_name);
  int32_t *size = *(int32_t*)check_user_addr_can_read(f->esp + 2* ptr_size, ptr_size);
  
  bool result = filesys_create(flie_name,size);

  // printf("result:%d \n",result);
  f->eax = result;
}

void sys_call_remove(struct intr_frame* f) {
  const char *flie_name = *(char**)check_user_addr_can_read(f->esp + ptr_size, ptr_size);
  check_str_can_read(flie_name);

  bool result = filesys_remove(flie_name);
  f->eax = result;
}

void sys_call_open(struct intr_frame* f) {
  const char *flie_name = *(char**)check_user_addr_can_read(f->esp + ptr_size, ptr_size);
  check_str_can_read(flie_name);

  struct file* res = filesys_open(flie_name);

  if(res == NULL)
  {
    f->eax = -1;
    return;
  }
  
  struct thread *t_cur = thread_current();

  int fd = t_cur->fd_can_allocate++;
  struct file_opened* entry_ptr = (struct file_opened*)malloc(sizeof(struct file_opened));
  entry_ptr->fd = fd;
  entry_ptr->file_ptr = res;

  list_push_back(&t_cur->file_list,&entry_ptr->file_elem);
  
  f->eax = fd;
}

void sys_call_close(struct intr_frame* f) {
  const int fd = *(int*)check_user_addr_can_read(f->esp + ptr_size, ptr_size);

  struct file_opened* file_list_entry = get_file(fd);

  if ( file_list_entry != NULL) {
    file_close(file_list_entry->file_ptr);
    list_remove(&file_list_entry->file_elem);
    free(file_list_entry);
  }
}

void sys_call_filesize(struct intr_frame* f) {
  const int fd = *(int*)check_user_addr_can_read(f->esp + ptr_size, ptr_size);
  struct file_opened* file_list_entry = get_file(fd);

  if(file_list_entry == NULL)
  {
    f->eax = -1;
  } else {
    f->eax = file_length(file_list_entry->file_ptr);
  }
  // printf("fd %d\n",fd);
}

void sys_call_read(struct intr_frame* f) {
  const int fd = *(int*)check_user_addr_can_read(f->esp + ptr_size, ptr_size);
  const uint32_t *buffer = *(uint32_t**)check_user_addr_can_read(f->esp + 2 * ptr_size, ptr_size);
  const int size = *(int*)check_user_addr_can_read(f->esp + 3 * ptr_size, ptr_size);
  // printf("size %d\n",size);
  // printf("buffer addr:%p\n",buffer);
  check_user_addr_can_read(buffer,size);

  if(fd == 0) {
    for(int i = 0;i < size; i++) {
      *(uint8_t*)(buffer+i) = input_getc();
    }
    return;
  }
  struct file_opened* file_list_entry = get_file(fd);
  if (file_list_entry == NULL) {
    f->eax = -1;
    return;
  }
  f->eax = file_read(file_list_entry->file_ptr,buffer,size);
}

void sys_call_write(struct intr_frame* f) {
  int fd = *(int *)check_user_addr_can_read(f->esp + ptr_size, ptr_size);
  size_t buf_size = *(size_t *)check_user_addr_can_read(f->esp + 3 * ptr_size, ptr_size);
  const char *buf = *(char **)check_user_addr_can_read(f->esp + 2 * ptr_size, ptr_size);
  check_user_addr_can_read(buf,buf_size); 
  if (fd == 1) {
    putbuf(buf, buf_size);
    f->eax = buf_size;
    return;
  } else {
    struct file_opened* file_list_entry = get_file(fd);
    if(file_list_entry == NULL) {
      f->eax = -1;
      return;
    } else {
      f->eax = file_write(file_list_entry->file_ptr, buf, buf_size);
      // printf("wirte eax %d \n",f->eax);
    }
  }
}

void sys_call_exec(struct intr_frame* f) {
  char *cmd_line = *(char **)check_user_addr_can_read(f->esp + ptr_size, ptr_size);
  check_str_can_read(cmd_line);
  f->eax = process_execute(cmd_line);
  // printf("child_pid %d \n",f->eax);
}


void sys_call_wait(struct intr_frame* f) {
  int pid = *(int *)check_user_addr_can_read(f->esp + ptr_size, sizeof(int));
  f->eax = process_wait(pid);
}

void sys_call_exit(struct intr_frame* f) {
  int exit_code = *(int *)check_user_addr_can_read(f->esp + ptr_size, sizeof(int));
  thread_current()->exit_code = exit_code;
  thread_exit();
}

void sys_call_seek(struct intr_frame* f) {
  int fd = *(int *)check_user_addr_can_read(f->esp + ptr_size, ptr_size);
  int32_t pos  = *(int *)check_user_addr_can_read(f->esp + 2 * ptr_size, ptr_size);

  struct file_opened* file_list_entry = get_file(fd);
  if(file_list_entry != NULL) {
    file_seek(file_list_entry->file_ptr,pos);
  }
}

void sys_call_practice(struct intr_frame* f) {
  int num = *(int *)check_user_addr_can_read(f->esp + ptr_size, ptr_size);
  f->eax = num + 1;
}

void sys_call_compute_e(struct intr_frame* f) {
  // 保存线程fpu
  struct thread* t_cur = thread_current();
  if(t_cur->fpu_flag == true) {
    asm volatile("fnsave (%%eax) \n" ::"a"(t_cur->fpu_state));
  } else {
    fpu_enable();
    // 初次使用fpu
    asm volatile(
          "fnclex \n"
          "fninit \n");
    t_cur->fpu_state = (fpu_t *)malloc(sizeof(fpu_t));
    t_cur->fpu_flag = true;
  }
  int num = *(int *)check_user_addr_can_read(f->esp + ptr_size, ptr_size);
  float e = 0.0;
  for (int i = 0; i <= num; i++) {
   e += 1.0 / factorial(i);
  }
  // 拷贝
  memcpy(&f->eax, &e, sizeof(int));
  // 恢复线程fpu，并关闭fpu
  asm volatile("frstor (%%eax) \n" ::"a"(t_cur->fpu_state));
  fpu_disable();
}


void sys_call_sys_pt_create(struct intr_frame* f) {
}

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = (uint32_t*)check_user_addr_can_read((uint32_t*)f->esp,sizeof(uint32_t));

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  /* printf("System call number: %d\n", args[0]); */

  switch (args[0]) {
    case SYS_HALT:
      sys_call_halt();
      break;
    case SYS_EXIT:
      sys_call_exit(f);
      break;
    case SYS_EXEC:
      sys_call_exec(f);
      break;
    case SYS_WAIT:
      sys_call_wait(f);
      break;
    case SYS_CREATE:
      sys_call_create(f);
      break;
    case SYS_REMOVE:
      sys_call_remove(f);
      break;
    case SYS_OPEN:
      sys_call_open(f);
      break;
    case SYS_FILESIZE:
      sys_call_filesize(f);
      break;
    case SYS_READ:
      sys_call_read(f);
      break;
    case SYS_WRITE:
      sys_call_write(f);
      break;
    case SYS_SEEK:
      sys_call_seek(f);
      break;
    case SYS_CLOSE:
      sys_call_close(f);
      break;
    case SYS_PRACTICE:
      sys_call_practice(f);
      break;
    case SYS_COMPUTE_E:
      sys_call_compute_e(f);
      break;
    case SYS_PT_CREATE:
      sys_call_sys_pt_create(f);
    default:
      // 处理未知的系统调用类型
      break;
  }

}
