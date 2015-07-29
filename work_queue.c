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
        /*����ȴ�����Ϊ0���Ҳ������̳߳أ���������״̬; ע��
        pthread_cond_wait��һ��ԭ�Ӳ������ȴ�ǰ����������Ѻ�����*/
        while (work_queue->cur_queue_size == 0 && !work_queue->shutdown)
        {
            //printf ("thread 0x%x is waiting\n", (unsigned int)pthread_self ());
            pthread_cond_wait (&(work_queue->queue_ready), &(work_queue->queue_lock));
        }
        /*�̳߳�Ҫ������*/
        if (work_queue->shutdown)
        {
            /*����break,continue,return����ת��䣬ǧ��Ҫ�����Ƚ���*/
            pthread_mutex_unlock (&(work_queue->queue_lock));
            printf ("thread 0x%x will exit\n", (unsigned int)pthread_self ());
            pthread_exit (NULL);
        }
        //printf ("thread 0x%x is starting to work\n", (unsigned int)pthread_self ());
        /*assert�ǵ��Եĺð���*/
        assert (work_queue->cur_queue_size != 0);
        assert (work_queue->queue_head != NULL);
        
        /*�ȴ����г��ȼ�ȥ1����ȡ�������е�ͷԪ��*/
        work_queue->cur_queue_size--;
        work_t *work = work_queue->queue_head;
        work_queue->queue_head = work->next;
        pthread_mutex_unlock (&(work_queue->queue_lock));
        /*���ûص�������ִ������*/
        (*(work->process)) (work->arg);
        free (work);
        work = NULL;
    }
    /*��һ��Ӧ���ǲ��ɴ��*/
    pthread_exit(NULL);
}

/*���̳߳��м�������*/
int queue_add_work(work_queue_t *work_queue, void *(*process) (void *arg), void *arg)
{
    /*����һ��������*/
    work_t *new_work =
        (work_t *) malloc (sizeof (work_t));
    new_work->process = process;
    new_work->arg = arg;
    new_work->next = NULL;/*�����ÿ�*/
    pthread_mutex_lock (&(work_queue->queue_lock));
    /*��������뵽�ȴ�������*/
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
    /*���ˣ��ȴ��������������ˣ�����һ���ȴ��̣߳�
    ע����������̶߳���æµ�����û���κ�����*/
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

/*�����̳߳أ��ȴ������е����񲻻��ٱ�ִ�У������������е��̻߳�һֱ
����������������˳�*/
int work_queue_destroy(work_queue_t *work_queue)
{
    if (work_queue->shutdown)
        return -1;/*��ֹ���ε���*/
    work_queue->shutdown = 1;
    /*�������еȴ��̣߳��̳߳�Ҫ������*/
    pthread_cond_broadcast (&(work_queue->queue_ready));
    /*�����ȴ��߳��˳�������ͳɽ�ʬ��*/
    int i;
    for (i = 0; i < work_queue->max_thread_num; i++)
        pthread_join (work_queue->threadid[i], NULL);
    free (work_queue->threadid);
    /*���ٵȴ�����*/
    work_t *head = NULL;
    while (work_queue->queue_head != NULL)
    {
        head = work_queue->queue_head;
        work_queue->queue_head = work_queue->queue_head->next;
        free (head);
    }
    /*���������ͻ�����Ҳ����������*/
    pthread_mutex_destroy(&(work_queue->queue_lock));
    pthread_cond_destroy(&(work_queue->queue_ready));
    
    free(work_queue);
    /*���ٺ�ָ���ÿ��Ǹ���ϰ��*/
    work_queue=NULL;
    return 0;
}