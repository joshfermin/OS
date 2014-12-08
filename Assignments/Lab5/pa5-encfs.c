/*
  Encrypted Filesystem using FUSE

  By: Josh Fermin & Louis BOUDDHOU
*/

#define FUSE_USE_VERSION 28
#define HAVE_SETXATTR

// fuse_get_context
// allows to have a relevant context to execute many operations.
#define ENC_DATA ((struct encrypt *) fuse_get_context()->private_data)

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 700
// For open_memstream()
#define _POSIX_C_SOURCE 200809L
#endif

#include "aes-crypt.h"
#include <linux/limits.h>
#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#define ENCRYPT 1
#define DECRYPT 0
#define PASS -1

#define ENC_ATTR "user.pa4-encfs.encrypted"
#define ENCRYPTED "true"
#define UNENCRYPTED "false"


// data structure that stores root directory and passphrase
struct encrypt {
	char *root;
	char *key;
};

// Need mount point - store in main and then when you need a path for something
// call this function to create the path for you which will be relative to the
// root of the mount point.
static void encfs_fullpath(char fpath[PATH_MAX], const char *path)
{
    strcpy(fpath, ENC_DATA->root); // copies root dir into array pointed by fpath
    strncat(fpath, path, PATH_MAX); // appends the first PATH_MAX chars of path to fpath
}

static int encfs_getattr(const char *path, struct stat *stbuf)
{
	int res;
	char fpath[PATH_MAX]; 
	encfs_fullpath(fpath, path);

	/*
		Upon successful completion, lstat() shall return 0. 
		Otherwise, it shall return -1 and set errno to indicate 
		the error.
	*/
	res = lstat(fpath, stbuf); // lsat creates an infinite loop
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_access(const char *path, int mask)
{
	int res;
	char fpath[PATH_MAX]; 
	encfs_fullpath(fpath, path);

	res = access(path, mask);   
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_readlink(const char *path, char *buf, size_t size)
{
	int res;
	char fpath[PATH_MAX]; 
	encfs_fullpath(fpath, path);

	res = readlink(path, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}


static int encfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	DIR *dp;
	struct dirent *de;

	(void) offset;
	(void) fi;

	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);
	dp = opendir(fpath);
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		if (filler(buf, de->d_name, &st, 0))
			break;
	}

	closedir(dp);
	return 0;
}

static int encfs_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	/* On Linux this could just be 'mknod(path, mode, rdev)' but this
	   is more portable */
	if (S_ISREG(mode)) {
		res = open(path, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo(path, mode);
	else
		res = mknod(path, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_mkdir(const char *path, mode_t mode)
{
	int res;

	res = mkdir(path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_unlink(const char *path)
{
	int res;

	res = unlink(path);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_rmdir(const char *path)
{
	int res;

	res = rmdir(path);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_symlink(const char *from, const char *to)
{
	int res;

	res = symlink(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_rename(const char *from, const char *to)
{
	int res;

	res = rename(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_link(const char *from, const char *to)
{
	int res;

	res = link(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_chmod(const char *path, mode_t mode)
{
	int res;

	res = chmod(path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_chown(const char *path, uid_t uid, gid_t gid)
{
	int res;

	res = lchown(path, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_truncate(const char *path, off_t size)
{
	int res;

	res = truncate(path, size);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_utimens(const char *path, const struct timespec ts[2])
{
	int res;
	struct timeval tv[2];

	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;

	res = utimes(path, tv);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_open(const char *path, struct fuse_file_info *fi)
{
	int res;

	res = open(path, fi->flags);
	if (res == -1)
		return -errno;

	close(res);
	return 0;
}

static int encfs_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	// initialize file and temp files for memory storage
	// also xattr data information 
	FILE *file;
	FILE *tempfile;
	char *tempdata;
	size_t tempsize;
	
	char xattrval[8];
	ssize_t xattrlen;
	
	// default action is to pass
	int action = PASS;
	
	int res;
	
	//fuse to make directory not root
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);

	(void) fi;
	
	// open file
	file = fopen(fpath, "r");
	if (file == NULL)
		return -errno;
		
	// opem memory stream
	tempfile = open_memstream(&tempdata, &tempsize);
	if (tempfile == NULL)
		return -errno;

	// check if decrypting or now, if it is encrypted then we do
	// otherwise do nothing
	xattrlen = getxattr(fpath, ENC_ATTR, xattrval, 8);
	if(xattrlen != -1 && strcmp(xattrval, ENCRYPTED) == 0) {
		action = DECRYPT;
	}
	
	do_crypt(file, tempfile, action, ENC_DATA->key);
	fclose(file);

	// flush/write temp file in memory in user space
	fflush(tempfile);
	// seek according to the offset from memory
	fseek(tempfile, offset, SEEK_SET);
	
	// open up temp file and read
	res = fread(buf, 1, size, tempfile);
	if (res == -1)
		res = -errno;
	
	// close temp file
	fclose(tempfile);

	return res;
}

static int encfs_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	int fd;
	int res;

	(void) fi;
	fd = open(path, O_WRONLY);
	if (fd == -1)
		return -errno;

	res = pwrite(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	close(fd);
	return res;
}

static int encfs_statfs(const char *path, struct statvfs *stbuf)
{
	int res;

	res = statvfs(path, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_create(const char* path, mode_t mode, struct fuse_file_info* fi) {

    (void) fi;

    int res;
    res = creat(path, mode);
    if(res == -1)
	return -errno;

    close(res);

    return 0;
}


static int encfs_release(const char *path, struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) fi;
	return 0;
}

static int encfs_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) isdatasync;
	(void) fi;
	return 0;
}

#ifdef HAVE_SETXATTR
static int encfs_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
	int res = lsetxattr(path, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int encfs_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	int res = lgetxattr(path, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int encfs_listxattr(const char *path, char *list, size_t size)
{
	int res = llistxattr(path, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int encfs_removexattr(const char *path, const char *name)
{
	int res = lremovexattr(path, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */

static struct fuse_operations encfs_oper = {
	.getattr	= encfs_getattr,
	.access		= encfs_access,
	.readlink	= encfs_readlink,
	.readdir	= encfs_readdir,
	.mknod		= encfs_mknod,
	.mkdir		= encfs_mkdir,
	.symlink	= encfs_symlink,
	.unlink		= encfs_unlink,
	.rmdir		= encfs_rmdir,
	.rename		= encfs_rename,
	.link		= encfs_link,
	.chmod		= encfs_chmod,
	.chown		= encfs_chown,
	.truncate	= encfs_truncate,
	.utimens	= encfs_utimens,
	.open		= encfs_open,
	.read		= encfs_read,
	.write		= encfs_write,
	.statfs		= encfs_statfs,
	.create         = encfs_create,
	.release	= encfs_release,
	.fsync		= encfs_fsync,
#ifdef HAVE_SETXATTR
	.setxattr	= encfs_setxattr,
	.getxattr	= encfs_getxattr,
	.listxattr	= encfs_listxattr,
	.removexattr	= encfs_removexattr,
#endif
};

void encfs_usage()
{
	fprintf(stderr, "usage: ./pa5-encfs encryption_key mirror_dir mount_point\n");
	abort();
}

int main(int argc, char *argv[])
{
	fprintf(stderr, "%d\n", argc);
	fprintf(stderr, "%s\n", *argv);
	struct encrypt *enc_data;

	// need to check if root is running... If it is return error
	if ((getuid() == 0) || (geteuid() == 0)) {
		fprintf(stderr, "Running as root opens unnacceptable security holes\n");
		return 1;
    }

    // check that there are more than 3 args i.e. pa5-encfs encryption_key mirror_dir mount_point
    if ((argc < 3) || (argv[argc-2][0] == '-') || (argv[argc-1][0] == '-')) {
    	encfs_usage(); // if not show usage and abort
    }

    // need space for the data
    enc_data = malloc(sizeof(struct encrypt));
    if (enc_data == NULL) {
		perror("main calloc");
		abort();
    }

    // will give path to directory to be mirrored/encrypted
    // i.e.  mirror_dir in pa5-encfs encryption_key mirror_dir mount_point
    enc_data->root = realpath(argv[argc-2], NULL);

    // put key into encrypt struct and then set it up for argc.
    enc_data->key = argv[argc-3];
	argv[argc-3] = argv[argc-1];
    argv[argc-2] = NULL;
    argv[argc-1] = NULL;
    argc -= 2;
    
    
	umask(0);
	return fuse_main(argc, argv, &encfs_oper, enc_data);
}
