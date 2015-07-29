#ifndef _WORK_QUEUE_H_
#define _WORK_QUEUE_H_

/*
*线程池里所有运行和等待的任务都是一个work_t
*由于所有任务都在链表里，所以是一个链表结构
*/
typedef struct work_s
{
    /*回调函数，任务运行时会调用此函数，注意也可声明成其它形式*/
    void *(*process) (void *arg);
    void *arg;/*回调函数的参数*/
    struct work_s *next;
} work_t;

/*线程池结构*/
typedef struct work_queue_s
{
    pthread_mutex_t queue_lock;
    pthread_cond_t queue_ready;
    /*链表结构，线程池中所有等待任务*/
    work_t *queue_head;
    /*是否销毁线程池*/
    int shutdown;
    pthread_t *threadid;
    /*线程池中允许的活动线程数目*/
    int max_thread_num;
    /*当前等待队列的任务数目*/
    int cur_queue_size;
} work_queue_t;

extern work_queue_t *work_queue_init(int max_thread_num);
extern int queue_add_work (work_queue_t *work_queue, void *(*process) (void *arg), void *arg);
extern int work_queue_destroy(work_queue_t *work_queue);

#endif /* _WORK_QUEUE_H_ */