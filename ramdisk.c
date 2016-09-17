#include <ramdisk.h>
#include <heap.h>
#include <debug.h>
#include <string.h>
#include <video.h>
#include <dayos/message.h>
#include <dayos/dayos.h>
#include <dayos/driver.h>
#include <sys/stat.h>
#include <string.h>
#include <dayos/vfs.h>
#include <stdlib.h>

// RAM-Disk ist eine tar-file
typedef struct
{
	char filename[100];
	char mode[8];
	char uid[8];
	char gid[8];
	char size[12];
	char mtime[12];
	char chksum[8];
	char typeflag;
}tar_header_t;

static tar_header_t** files;
static tar_header_t* first_file;
static uint32_t filecount = 0;

static uint32_t get_size(const char* in)
{
 	unsigned int size = 0;
	unsigned int j;
	unsigned int count = 1;
	 
	for (j = 11; j > 0; j--, count *= 8)
		size += ((in[j - 1] - '0') * count);
	 
	return size; 
}

static uint32_t count_files()
{
	uint32_t i = 0;
	tar_header_t* header;
	uintptr_t address = (uintptr_t) first_file;
	header = first_file;
			
	while(header->filename[0] != '\0')
	{				
		uint32_t size = get_size(header->size);
		address += ((size / 512) + 1) * 512;
		
		if(size % 512)
			address += 512;
			
		header = (tar_header_t*) address;
								
		i++;
	}

	return i;	
}

static void add_files_to_list()
{
	assert(files != NULL);
	
	uint32_t i = 0;
	tar_header_t* header = first_file;
	uintptr_t address = (uintptr_t) first_file;
			
	while(header->filename[0] != '\0')
	{				
		files[i] = header;
		uint32_t size = get_size(header->size);
		address += ((size / 512) + 1) * 512;
		
		if(size % 512)
			address += 512;
		
		header = (tar_header_t*) address;
		i++;
	}
}

/// FIXME: Testen, ob gefragter Pfad eine Datei oder ein Ordner ist!
uintptr_t RamDiskFileContent(const char* name)
{
	if(files == NULL)
	{
		DebugPrintf("[ RAMDISK ] Could not open file '%s' in %s line %d\n", name, __FILE__, __LINE__);
		return 0;
	}

	int i;
	for(i = 0; i < filecount; i++)
	{
		if(!strcmp(name, files[i]->filename))
		{
			return (uintptr_t) ((char*) files[i] + 512);
		}
	}
	
	DebugPrintf("[ RAMDISK ] File '%s' not found in %s line %d\n", name, __FILE__, __LINE__);
	return 0;
}

tar_header_t* GetRamDiskFile(const char* name)
{
	if(files == NULL)
	{
		DebugPrintf("[ RAMDISK ] Could not open file '%s' in %s line %d\n", name, __FILE__, __LINE__);
		return 0;
	}

	int i;
	for(i = 0; i < filecount; i++)
	{
		if(!strcmp(name, files[i]->filename))
		{
			return files[i];
		}
	}
	
	DebugPrintf("[ RAMDISK ] File '%s' not found in %s line %d\n", name, __FILE__, __LINE__);
	return NULL;
}

tar_header_t* GetRamDiskFileByName(const char* path, const char* name)
{
	char fullpath[512];
	strcpy(fullpath, ".");
	
	if(strlen(path) > 1)
		strcat(fullpath, path);
	
	strcat(fullpath, "/");
	strcat(fullpath, name);
	
	return GetRamDiskFile(fullpath);
}

uintptr_t RamDiskFileContentByName(const char* path, const char* name)
{
	char fullpath[512];
	strcpy(fullpath, ".");
	
	if(strlen(path) > 1)
		strcat(fullpath, path);
	
	strcat(fullpath, "/");
	strcat(fullpath, name);
	
	return RamDiskFileContent(fullpath);
}

tar_header_t* GetRamDiskFileRel(const char* path)
{
	char fullpath[512];
	strcpy(fullpath, ".");
	
	if(strlen(path) >= 1)
		strcat(fullpath, path);

	return GetRamDiskFile(fullpath);
}

uintptr_t RamDiskFileContentRel(const char* path)
{
	char fullpath[512];
	strcpy(fullpath, ".");
	
	if(strlen(path) > 1)
		strcat(fullpath, path);
	
	return RamDiskFileContent(fullpath);
}

void InitRamdisk(uintptr_t addr)
{
	assert(addr != 0);
	
	DebugPrintf("[ RAMDISK ] RAM-Disk at 0x%x\n", addr);
	
	first_file = (tar_header_t*) addr;//(addr + 512);
	filecount = count_files();
	
	assert(filecount != 0);
	
	DebugPrintf("[ RAMDISK ] RAM-Disk contains %d files\n", filecount);
	
	files = (tar_header_t**) kmalloc(sizeof(tar_header_t*) * filecount);
	add_files_to_list();
}

void ramdisk_process()
{
	DebugLog("[ RAMDISK ] RAM-Disk daemon started.");

	// Wait for VFS to crop up
	pid_t pid = 0;
	while((pid = get_service_pid("vfs")) == 0) sleep(50);
	
	int retval = vfs_mount_ramdisk("/drives/roramdisk", VFS_MODE_RO);
	if (retval == SIGNAL_FAIL)
	{
		DebugLog("[ RAMDISK ] Could not mount device!");
		exit(-1);
		while(1);
	}
	
	DebugLog("[ RAMDISK ] Mounted ramdisk to '/drives/roramdisk'");
	
	message_t msg;
	struct vfs_request* rq = (struct vfs_request*) &msg.message;
	struct vfs_file* vfile = (struct vfs_file*) &msg.message;
	char* data = NULL;
	tar_header_t* file;
	
	while(1)
	{
		while (receive_message(&msg, MESSAGE_ANY) != MESSAGE_RECEIVED)
				sleep(10);

		switch(msg.signal)
		{
			case VFS_SIGNAL_OPEN:
				if(rq->mode != VFS_MODE_RO || !GetRamDiskFileRel(rq->path))
					msg.signal = SIGNAL_FAIL;
				else
					msg.signal = SIGNAL_OK;

				send_message(&msg, msg.sender);
			break;
			
			case VFS_SIGNAL_STAT: {
				struct stat* stat = (struct stat*) &msg.message;
				tar_header_t* f = GetRamDiskFileRel(rq->path);
				
				if(!f)
				{
					DebugLog("[ RAMDISK ] Could not stat file!");
					msg.signal = SIGNAL_FAIL;
					send_message(&msg, msg.sender);
					break;
				}

				stat->st_dev = msg.receiver;
				stat->st_size = get_size(f->size);
				
				//sscanf(f->gid, "%d", &stat->st_gid);
				/*stat->st_gid = f->gid;
				stat->st_uid = f->uid;
				stat->st_mode = f->mode;
				stat->st_mtim = f->mtime;*/
				
				msg.signal = SIGNAL_OK;
				send_message(&msg, msg.sender);
			}
			break;
			
			case VFS_SIGNAL_READ: {
				tar_header_t* f = GetRamDiskFileRel(rq->path);
				char* data = ((char*) f + 512);
				size_t fsz = get_size(f->size);
				size_t sz = fsz;
				if(rq->size < sz) sz = rq->size;
				
				if(!f || rq->offset + sz > fsz)
				{
					msg.signal = SIGNAL_FAIL;
					send_message(&msg, msg.sender);
					break;
				}

				write_message_stream(data+rq->offset, sz, msg.sender);
			}
			break;
			
			case VFS_SIGNAL_OPEN_DIR: {
				// Prepare filename for being a directory
				size_t pathlen = strlen(rq->path);
				
				if(rq->path[pathlen-1] != '/' && pathlen < sizeof(rq->path) - 1)
				{
					rq->path[pathlen] = '/';
					rq->path[pathlen+1] = 0;
				}
				
				file = GetRamDiskFileRel(rq->path);
				
				if(!file)
				{
					msg.signal = SIGNAL_FAIL;
					send_message(&msg, msg.sender);
					break;
				}
				
				// Find first entry of the directory
				int i;
				size_t dirname_len = strlen(file->filename);
				for(i = 0; i < filecount; i++)
				{
					DebugPrintf("Comparing %s to %s\n", files[i]->filename + 1, rq->path);
					if(!strncmp(files[i]->filename + 1, rq->path, dirname_len))
					{
						i++;
						break;
					}
				}
			
				vfile->child_nid = i;
				strcpy(vfile->path, files[i-1]->filename + 1);

				msg.size = sizeof(struct vfs_file);
				msg.signal = SIGNAL_OK;
				send_message(&msg, msg.sender);
			}
			break;
			
			case VFS_SIGNAL_READ_DIR: {
				
				if(rq->param < 0 || rq->param >= filecount)
				{
					msg.signal = SIGNAL_FAIL;
					send_message(&msg, msg.sender);
					break;
				}
				
				size_t cur_item = rq->param;
				size_t curfile_len;
				size_t len = strlen(rq->path) + 1;
				const char* last_slash;
				
				for(cur_item = rq->param; cur_item < filecount && last_slash && last_slash != &file->filename[curfile_len - 1]; cur_item++)
				{
					file = files[cur_item];
					curfile_len = strlen(file->filename);
					last_slash = strchr(&file->filename[len], '/');
				}
				
				if(cur_item >= filecount)
				{
					msg.signal = SIGNAL_FAIL;
					send_message(&msg, msg.sender);
					break;
				}
				
				vfile->nid = cur_item;
				vfile->child_nid = cur_item + 1;
				debug_printf("%d\n", cur_item + 1);
				
				strcpy(vfile->path, file->filename);
				msg.signal = SIGNAL_OK;
				send_message(&msg, msg.sender);
			}
			break;
			
			default:
				DebugPrintf("[ RAMDISK ] Unknown signal %d from %d\n", msg.signal, msg.sender);
		}
	}
}
