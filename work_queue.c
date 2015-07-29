#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>

#include "work_queue.h"

void *thread_routine(void *arg)
{
	work_queue_t *work_queue = (work_queue_t *)arg;
    printf ("starting thread 0x%x\n", (unsigned int)pthread_self ());
    while (1)
    {
        pthread_mutex_lock (&(work_queue->queue_lock));
        /*如果等待队列为0并且不销毁线程池，则处于阻塞状态; 注意
        pthread_cond_wait是一个原子操作，等待前会解锁，唤醒后会加锁*/
        while (work_queue->cur_queue_size == 0 && !work_queue->shutdown)
        {
            //printf ("thread 0x%x is waiting\n", (unsigned int)pthread_self ());
            pthread_cond_wait (&(work_queue->queue_ready), &(work_queue->queue_lock));
        }
        /*线程池要销毁了*/
        if (work_queue->shutdown)
        {
            /*遇到break,continue,return等跳转语句，千万不要忘记先解锁*/
            pthread_mutex_unlock (&(work_queue->queue_lock));
            printf ("thread 0x%x will exit\n", (unsigned int)pthread_self ());
            pthread_exit (NULL);
        }
        //printf ("thread 0x%x is starting to work\n", (unsigned int)pthread_self ());
        /*assert是调试的好帮手*/
        assert (work_queue->cur_queue_size != 0);
        assert (work_queue->queue_head != NULL);
        
        /*等待队列长度减去1，并取出链表中的头元素*/
        work_queue->cur_queue_size--;
        work_t *work = work_queue->queue_head;
        work_queue->queue_head = work->next;
        pthread_mutex_unlock (&(work_queue->queue_lock));
        /*调用回调函数，执行任务*/
        (*(work->process)) (work->arg);
        free (work);
        work = NULL;
    }
    /*这一句应该是不可达的*/
    pthread_exit(NULL);
}

/*向线程池中加入任务*/
int queue_add_work(work_queue_t *work_queue, void *(*process) (void *arg), void *arg)
{
    /*构造一个新任务*/
    work_t *new_work =
        (work_t *) malloc (sizeof (work_t));
    new_work->process = process;
    new_work->arg = arg;
    new_work->next = NULL;/*别忘置空*/
    pthread_mutex_lock (&(work_queue->queue_lock));
    /*将任务加入到等待队列中*/
    work_t *member = work_queue->queue_head;
    if (member != NULL)
    {
        while (member->next != NULL)
            member = member->next;
        member->next = new_work;
    }
    else
    {
        work_queue->queue_head = new_work;
    }
    assert (work_queue->queue_head != NULL);
    work_queue->cur_queue_size++;
    pthread_mutex_unlock (&(work_queue->queue_lock));
    /*好了，等待队列中有任务了，唤醒一个等待线程；
    注意如果所有线程都在忙碌，这句没有任何作用*/
    pthread_cond_signal (&(work_queue->queue_ready));
	return 0;
}

work_queue_t * work_queue_init(int max_thread_num)
{
	work_queue_t *work_queue = (work_queue_t *) malloc (sizeof (work_queue_t));
    pthread_mutex_init (&(work_queue->queue_lock), NULL);
    pthread_cond_init (&(work_queue->queue_ready), NULL);
    work_queue->queue_head = NULL;
    work_queue->max_thread_num = max_thread_num;
    work_queue->cur_queue_size = 0;
    work_queue->shutdown = 0;
    work_queue->threadid =
        (pthread_t *) malloc (max_thread_num * sizeof (pthread_t));
    int i = 0;
    for (i = 0; i < max_thread_num; i++)
    {
        pthread_create (&(work_queue->threadid[i]), NULL, thread_routine,
                (void *)work_queue);
    }
	return work_queue;
}

/*销毁线程池，等待队列中的任务不会再被执行，但是正在运行的线程会一直
把任务运行完后再退出*/
int work_queue_destroy(work_queue_t *work_queue)
{
    if (work_queue->shutdown)
        return -1;/*防止两次调用*/
    work_queue->shutdown = 1;
    /*唤醒所有等待线程，线程池要销毁了*/
    pthread_cond_broadcast (&(work_queue->queue_ready));
    /*阻塞等待线程退出，否则就成僵尸了*/
    int i;
    for (i = 0; i < work_queue->max_thread_num; i++)
        pthread_join (work_queue->threadid[i], NULL);
    free (work_queue->threadid);
    /*销毁等待队列*/
    work_t *head = NULL;
    while (work_queue->queue_head != NULL)
    {
        head = work_queue->queue_head;
        work_queue->queue_head = work_queue->queue_head->next;
        free (head);
    }
    /*条件变量和互斥量也别忘了销毁*/
    pthread_mutex_destroy(&(work_queue->queue_lock));
    pthread_cond_destroy(&(work_queue->queue_ready));
    
    free(work_queue);
    /*销毁后指针置空是个好习惯*/
    work_queue=NULL;
    return 0;
}