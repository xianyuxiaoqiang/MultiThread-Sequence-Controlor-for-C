/*
 * MultiThread Sequence Controlor for C
 *
 */

#ifdef NT
/* Windows */
#include <Winsock2.h>
#include <windows.h>
#include <winsock.h>
#define DEFAULT_CONFIG_FILE "C:\\C_MultiThread_Sequence_Controlor\\cmtsc.cfg"
#define DEFAULT_LOG_FILE "C:\\C_MultiThread_Sequence_Controlor\\log.txt"
#define GLOBAL_MEMMAP_NAME "Global\\c_mtsc_memmap"
#else
/* Linux & Solaris */
#define DEFAULT_CONFIG_FILE "/tmp/C_MultiThread_Sequence_Controlor/cmtsc.cfg"
#define DEFAULT_LOG_FILE "/tmp/C_MultiThread_Sequence_Controlor/log.txt"
#ifdef LINUX
/* Linux */
#else
/* Solaris */
#endif
#endif

#define DEFAULT_BP_NUM  100

typedef struct break_point_node_tag
{
	char* break_point_name;
	int break_point_id;
}break_point_node_t;
typedef struct break_point_list_tag
{
	int break_point_num;
	int break_point_num_max;
	int status_flag;	/* status_flag>=1: current break point id */
#ifdef NT
/* Windows */
	HANDLE h_sem;
#endif
	break_point_node_t node[1];
}break_point_list_t;
#ifdef NT
CRITICAL_SECTION cts;
#define MY_CLOSE_HANDLE(hd)\
{\
		if( hd != 0 )\
		{\
			CloseHandle(hd);\
			hd = 0;\
		}\
}
#endif

static break_point_node_t * find_node(char* break_point_name, break_point_list_t * list)
{
	int i;
	for( i=0;i<list->break_point_num;i++)
	{
		if( strcmp( break_point_name, list->node[i].break_point_name ) == 0 )
		{
			return &list->node[i];
		}
	}
	return NULL;
}
static int loging(char* break_point_name, char* msg)
{
	return 0;
}

extern int c_multithread_sequence_controlor(
    char* break_point_name,
    int wait_min,                           /* ms */
    int wait_max,                           /* ms */
    char* log_file_path,
    int conf_flag_or_bp_id					/* conf_flag_or_bp_id=-1: use config file to get id */
											/* conf_flag_or_bp_id>=1: break point id */
)
{
	break_point_list_t* bp_list;
	break_point_node_t* p_node;
	int time;
#ifdef NT
/* Windows */
    SECURITY_DESCRIPTOR sd;
    SECURITY_ATTRIBUTES sa;
    static HANDLE h_mem = NULL;
    static char *shmem_addr;
    DWORD win_ret = ERROR_ALREADY_EXISTS;
#endif
	int shmem_size = (DEFAULT_BP_NUM-1) * sizeof(break_point_node_t) + sizeof(break_point_list_t);/* todo: change by config file */
	
	
#ifdef NT
/* Windows */
	EnterCriticalSection(&cts);
	if(h_mem!=NULL)
	{
		LeaveCriticalSection(&cts);
		goto SKIP_MEMMAP_1;
	}
	if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION))
	{
		loging(break_point_name,"InitializeSecurityDescriptor error.");
		goto ERROR_END_2;
	}
	if (!SetSecurityDescriptorDacl(&sd, TRUE, (PACL) NULL, FALSE))
	{
		loging(break_point_name,"SetSecurityDescriptorDacl error.");
		goto ERROR_END_2;
	}

	sa.nLength = sizeof(sa);
	sa.lpSecurityDescriptor = &sd;
	sa.bInheritHandle = TRUE;

	h_mem = CreateFileMapping(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE, 0,
								(DWORD)shmem_size, GLOBAL_MEMMAP_NAME);
	if (h_mem == NULL)
	{
		loging(break_point_name,"CreateFileMapping error.");
		goto ERROR_END_2;
	}
	win_ret = GetLastError();
	shmem_addr = (char *)MapViewOfFile(h_mem, FILE_MAP_READ | FILE_MAP_WRITE,
								0, 0, 0);
	if( shmem_addr == NULL )
	{
		loging(break_point_name,"MapViewOfFile error.");
		goto ERROR_END_3;
	}
	bp_list = (break_point_list_t*)shmem_addr;
	if( win_ret != ERROR_ALREADY_EXISTS )
	{
		bp_list->h_sem = CreateSemaphore(NULL, 1, 1, NULL);
		if (bp_list->h_sem == NULL)
		{
			loging(break_point_name,"CreateSemaphore error.");
			goto ERROR_END_4;
		}
		bp_list->break_point_num = 1;
		bp_list->break_point_num_max = DEFAULT_BP_NUM;
		bp_list->status_flag = 1;
		bp_list->node[0].break_point_name = break_point_name;
		bp_list->node[0].break_point_id = conf_flag_or_bp_id;		/* todo : when conf_flag_or_bp_id <= 0 */
	}
	LeaveCriticalSection(&cts);
	goto WAIT_POINT;
	
SKIP_MEMMAP_1:
	bp_list = (break_point_list_t*)shmem_addr;
	WaitForSingleObject(bp_list->h_sem, INFINITE);
	p_node = find_node( break_point_name, bp_list );
	if( p_node == NULL )
	{
		if( bp_list->break_point_num == bp_list->break_point_num_max )
		{
			loging(break_point_name,"too many breakpoints.");
			ReleaseSemaphore(bp_list->h_sem,1,NULL );
			goto ERROR_END_1;
		}
		bp_list->node[bp_list->break_point_num].break_point_name = break_point_name;
		bp_list->node[bp_list->break_point_num].break_point_id = conf_flag_or_bp_id;		/* todo : when conf_flag_or_bp_id <= 0 */
		bp_list->break_point_num++;
	}
	ReleaseSemaphore(bp_list->h_sem,1,NULL );
WAIT_POINT:
	time = wait_min;
	while(time < wait_max && bp_list->status_flag < conf_flag_or_bp_id)
	{
		Sleep(wait_min);
		time += wait_min;
	}
	loging(break_point_name,"crossed.");
	WaitForSingleObject(bp_list->h_sem, INFINITE);
	bp_list->status_flag = conf_flag_or_bp_id + 1;
	ReleaseSemaphore(bp_list->h_sem,1,NULL );
	return 0;
		
#endif

	
ERROR_END_4:
	MY_CLOSE_HANDLE(shmem_addr)
ERROR_END_3:
	MY_CLOSE_HANDLE(h_mem)
ERROR_END_2:
	LeaveCriticalSection(&cts);
ERROR_END_1:
	return -1;
}

