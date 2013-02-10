/*
Copyright (c) 2013 by Chris Wade (cmw)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include <stdio.h>
#include <stdlib.h> 
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#define RCFS_MAGIC "r-c-f-s"
#define RCFS_SUPERBLOCK_OFF 0x1020

#define EXTRACT_FILE 1
#define LIST_FILE 2
#define PRINT_INFO 3
#define DUMP_FILES 4


extern int lzo1x_decompress_safe(const unsigned char *in, size_t in_len, unsigned char *out, size_t *out_len);

static char timestamp[200] = {0};
char *print_timestamp(unsigned int tvalue)
{
  struct tm *tm;
  time_t time = tvalue;

  tm = gmtime(&time);
  sprintf(timestamp, "%s", asctime(tm));
  timestamp[strlen(timestamp) - 1] = '\0';
  return timestamp;
}

typedef struct inode_ptr {
	unsigned long flags;
	unsigned int fname_addr;	/* filename offset */
	unsigned int phyoff;		/* file data offset */
	unsigned int size;			/* uncompressed file size */
	unsigned int timestamp;		/* modification timestamp */
	unsigned int unkn3;
	unsigned int unkn4;
} inode_ptr_s;

typedef struct file
{
    __uint32_t header_size;
    __uint32_t *boff;
    __uint32_t num_chunks;
} file_s;

typedef struct rcfs
{
	__uint32_t magic[2];	/* RCFS magic */
	__uint32_t unkn1;
	__uint32_t unkn2;
    __uint32_t size;        /* Raw disk size */
	__uint32_t ninodes;		/* Total number of inodes */
    __uint32_t inode_off;   /* Offset to inode block */
    __uint32_t inode_len;   /* Length of inode block */
    __uint32_t fname_off;   /* Offset to filename index block */
    __uint32_t fname_len;   /* Length of filename index block */
    __uint32_t data_off;    /* File data block start offset */
	__uint32_t data_len; 	/* Length of file data block */
    __uint32_t cbuflen;     /* Cache buffer length */
    FILE *fp;
    inode_ptr_s *inodes;
} rcfs_s;

/*
 * Flags used by RCFS
 */
// 1 << 46
#define RCFS_DIRECTORY 0x400000000000

/*
 * Open rcfs image
 */
rcfs_s *rcfs_open(char *filename)
{
    FILE *fp;
    rcfs_s *p;
    
    fp = fopen(filename, "r");
    if(!fp)
        return NULL;
    
    p = calloc(1, sizeof(rcfs_s));
    if(!p)
    {
        fclose(fp);
        return NULL;
    }
    
    // Read super block
    fseek(fp, RCFS_SUPERBLOCK_OFF, SEEK_SET);
	if(fread(p, 1, sizeof(rcfs_s), fp) != sizeof(rcfs_s))
        goto err;
    
    if(memcmp(p->magic, RCFS_MAGIC, 7) != 0)
       goto err;
    
    // Read inode block
    fseek(fp, p->inode_off, SEEK_SET);
    p->inodes = malloc(p->ninodes * sizeof(inode_ptr_s));
    if(fread(p->inodes, 1, p->ninodes * sizeof(inode_ptr_s), fp) != (p->ninodes * sizeof(inode_ptr_s)))
        goto err;

    p->fp = fp;
    
    return p;
    
err:
    fclose(fp);
    free(p->inodes);
    free(p);
    return NULL;
}

/* 
 * Close rcfs image
 */
void rcfs_close(rcfs_s *p)
{
    fclose(p->fp);
	free(p->inodes);
    free(p);
}

/*
 * Read a file junk and decompress
 */
size_t rcfs_read_chunk(rcfs_s *p, __uint8_t *buffer, size_t size, __uint32_t offset)
{
    unsigned char *inbuffer = malloc(size);
    size_t outlen = 0x4000;
    int ret;
	ret = fread(inbuffer, 1, size, p->fp);
    ret = lzo1x_decompress_safe((const unsigned char *)inbuffer, offset, (unsigned char *)buffer, &outlen);
	free(inbuffer);
    if(ret < 0)
        return 0;
    return outlen;
}

/* 
 * Read and decompress each chunk of file
 */
size_t rcfs_read_file(rcfs_s *p, __uint32_t inode_index, __uint8_t *buffer)
{
	int readBytes, len, i;
	__uint32_t num_chunks, header_size;
	__uint32_t chunk_size, posOff = 0;

	fseek(p->fp, p->inodes[inode_index].phyoff, SEEK_SET);
	fread(&header_size, 1, sizeof(__uint32_t), p->fp);
	num_chunks = ((header_size + (sizeof(__uint32_t) - 1)) / sizeof(__uint32_t)) - 1; 
	readBytes = 0;
	for(i=0;i < num_chunks;i++)
	{

		fseek(p->fp, p->inodes[inode_index].phyoff+sizeof(__uint32_t)+i*4, SEEK_SET);
		fread(&chunk_size, 1, sizeof(chunk_size), p->fp);
		fseek(p->fp, p->inodes[inode_index].phyoff+header_size+posOff, SEEK_SET);
		len = rcfs_read_chunk(p, (buffer+readBytes), chunk_size, (chunk_size-posOff-header_size));
		if(!len)
			break;
		readBytes += len;
		posOff += chunk_size-posOff-header_size;
	}
	return readBytes;
}

/*
 * List all files and directories in rcfs image
 */
void rcfs_list_files(rcfs_s *p)
{
    int i;
    char filename[1024] = {0};
    
    for(i=0;i < p->ninodes; i++)
	{
        fseek(p->fp, p->inodes[i].fname_addr, SEEK_SET);
        fread(filename, 1, 100, p->fp);
        printf("file: 0x%08lx 0x%08lx 0x%08x 0x%08x 0x%08x %s 0x%08x 0x%08x %s\n", 0x2000 + i * sizeof(inode_ptr_s), p->inodes[i].flags, p->inodes[i].fname_addr, p->inodes[i].phyoff, p->inodes[i].size, print_timestamp(p->inodes[i].timestamp), p->inodes[i].unkn3, p->inodes[i].unkn4, filename);
    }
}

/*
 * Lookup inode number from filename
 */
__uint32_t rcfs_inode_lookup(rcfs_s *p, char *_fname)
{
	int i;
    char filename[1024] = {0};

    for(i=0;i < p->ninodes; i++)
    {
        fseek(p->fp, p->inodes[i].fname_addr, SEEK_SET);
        fread(filename, 1, 100, p->fp);
		if(strncmp(_fname, filename, strlen(_fname)) == 0)
			return i;
	}
	return 0;
}

int main(int argc, char *argv[])
{
    rcfs_s *p;
    int cmd = 0;
    int argsvalid = 0;
    char *filename;
    
    if(argc >= 3)
    {
        if ((strcmp(argv[1], "-e") == 0) && argc == 4) {
            cmd = EXTRACT_FILE;
            filename = strdup(argv[3]);
        }
        if (strcmp(argv[1], "-l") == 0 )
            cmd = LIST_FILE;
        if (strcmp(argv[1], "-p") == 0 )
            cmd = PRINT_INFO;
        if (strcmp(argv[1], "-d") == 0 )
            cmd = DUMP_FILES;
        
        if(cmd)
            argsvalid = 1;
    }
    
    if ( !argsvalid ) {
        printf("Usage: \n");
        printf("       %s {-e|-l|-p|-d} image.bin {filename}\n", argv[0]);
        printf("       %s -e image.bin filename		- extracts filename\n", argv[0]);
        printf("       %s -l image.bin			- lists all files and directories\n", argv[0]);
        printf("       %s -p image.bin			- prints superblock information\n", argv[0]);
        printf("       %s -d image.bin          - dumps all files and directories\n", argv[0]);
        exit(1);
    }
    
    p = rcfs_open(argv[2]);
    if(!p)
    {
        printf("rcfs: Invalid rcfs image file %s\n", argv[2]);
        return 1;
    }
    switch(cmd) {
        case PRINT_INFO:
            printf("fs-rcfs: -------- superblock information--------\n");
			printf("size:		0x%08x\n", p->size);
			printf("cbuflen:	0x%08x\n", p->cbuflen);
			printf("data_off:	0x%08x\n", p->data_off);
			printf("data_len:	0x%08x\n", p->data_len);
			printf("inode_off:	0x%08x\n", p->inode_off);
			printf("inode_len:	0x%08x\n", p->inode_len);
			printf("fname_off:	0x%08x\n", p->fname_off);
			printf("fname_len:	0x%08x\n", p->fname_len);
			printf("inodes:		0x%08x\n", p->ninodes);
            break;
        case LIST_FILE:
            rcfs_list_files(p);
            break;
        case DUMP_FILES:
        {
            int i,len;
            char* ext;
            char filename[1024] = {0};
            char folder[1024] = {0};
            char destination[2048] = {0};
            __uint8_t *fdata;
            FILE *outfile;

            strcpy(folder, argv[2]);
            ext = strrchr(folder,'.');
            if (ext)
                folder[ext-folder] = '\0';
            mkdir(folder, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
            for(i=0;i < p->ninodes; i++)
            {
                fseek(p->fp, p->inodes[i].fname_addr, SEEK_SET);
                fread(filename, 1, 100, p->fp);
                sprintf(destination, "%s/%s", folder, filename);
                if(p->inodes[i].flags & RCFS_DIRECTORY)
                {
                    ext = strrchr(folder,'/');
                    if (!ext)
                        ext = filename;
                    if (strlen(ext) > 1 && strcmp(ext,".") != 0 && strcmp(ext,"..") != 0)
                    {
                        mkdir(destination, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
                        printf("Creating %s\n", filename);
                    }
                    continue;
                }
                fseek(p->fp, p->inodes[i].fname_addr, SEEK_SET);
                fread(filename, 1, 100, p->fp);
                printf("Extracting %s...\n", filename);
                fdata = malloc(p->inodes[i].size);
                len = rcfs_read_file(p, i, fdata);
                if(len > 0)
                {
                    outfile = fopen(destination, "w");
                    fwrite(fdata, 1, len, outfile);
                    fclose(outfile);
                } else {
                    printf("Failed to decompress file\n");
                }
            }
            free(fdata);
            break;
        }
        case EXTRACT_FILE:
		{
			int len = 0;
			int inode = rcfs_inode_lookup(p, filename);
			__uint8_t *fdata;
			FILE *outfile;
			if(!inode)
			{
				printf("Unable to find %s in image\n", filename);
				free(filename);
				free(fdata);
				break;
			}
			fdata = malloc(p->inodes[inode].size);
			len = rcfs_read_file(p, inode, fdata);
			if(len > 0)
			{
				outfile = fopen(filename, "w");
				fwrite(fdata, 1, len, outfile);
				fclose(outfile);
			} else {
				printf("Failed to decompress file\n");
			}
			printf("successfully extracted %s\n", filename);
			free(fdata);
			free(filename);
            break;
		}
    }
    rcfs_close(p);
    return 0;
}
