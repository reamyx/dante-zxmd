/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2005, 2008, 2009, 2010,
 *               2011, 2012, 2013, 2017
 *      Inferno Nettverk A/S, Norway.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. The above copyright notice, this list of conditions and the following
 *    disclaimer must appear in all copies of the software, derivative works
 *    or modified versions, and any portions thereof, aswell as in all
 *    supporting documentation.
 * 2. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by
 *      Inferno Nettverk A/S, Norway.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Inferno Nettverk A/S requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  sdc@inet.no
 *  Inferno Nettverk A/S
 *  Oslo Research Park
 *  Gaustadall閑n 21
 *  NO-0349 Oslo
 *  Norway
 *
 * any improvements or extensions that they make and grant Inferno Nettverk A/S
 * the rights to redistribute these changes.
 *
 */

#include "common.h"

#if HAVE_SHADOW_H && HAVE_GETSPNAM
#include <shadow.h>
#endif /* HAVE_SHADOW_H && HAVE_GETSPNAM */

#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>
#define BFSIZE 256
#define IDSIZE 16

const char *expandpath="/root/skdpwdck.sh";

static const char rcsid[] =
"$Id: auth_password.c,v 1.41.6.2 2017/01/31 08:17:38 karls Exp $";

static const char *
sockd_getpasswordhash(const char *login, char *pw, const size_t pwsize,
                      char *emsg, const size_t emsglen);
/*
 * Fetches the password hash for the username "login".
 * The returned hash is stored in "pw", which is of size "pwsize".
 *
 * Returns the password hash on success, or NULL on failure.  On failure,
 * emsg, which must be of size emsglen, contains the reason for the error.
 */

/* 通过指定的外部程序获取密码并转换成HASH,数据返回方法同上 */
static const char *
sockd_getpasswordhash_expand(const char *login, char *pw, const size_t pwsize,
                             char *emsg, const size_t emsglen,
                             const char *uspwd, const char *path);
 
 
int
passwordcheck(name, cleartextpw, emsg, emsglen)
   const char *name;
   const char *cleartextpw;
   char *emsg;
   size_t emsglen;
{
   const char *function = "passwordcheck()";
   const char *p;
   char visstring[MAXNAMELEN * 4], pwhash[MAXPWLEN],  *crypted;
   int rc;

   slog(LOG_DEBUG, "%s: name = %s, password = %s",
        function,
         str2vis(name,
                 strlen(name),
                 visstring,
                 sizeof(visstring)),
        cleartextpw == NULL ? "<empty>" : "<cleartextpw>");

   if (cleartextpw == NULL) {
      /*
       * No password to check.  I.e. the authmethod used does not care
       * about passwords, only whether the user exists or not. E.g.
       * rfc931/ident.
       */
      if (getpwnam(name) == NULL) {
         snprintf(emsg, emsglen, "no user \"%s\" found in system password file",
                  str2vis(name,
                          strlen(name),
                          visstring,
                          sizeof(visstring)));
         return -1;
      }
      else
         /*
          * User is in the passwordfile, and that is all we care about.
          */
         return 0;
   }
    
   /*
    * Else: the authmethod used requires us to match the password also.
    */

   /* usually need privileges to look up the password. */
   sockd_priv(SOCKD_PRIV_FILE_READ, PRIV_ON);
   p = sockd_getpasswordhash_expand(name,
                             pwhash,
                             sizeof(pwhash),
                             emsg,
                             emsglen, cleartextpw, expandpath);
   sockd_priv(SOCKD_PRIV_FILE_READ, PRIV_OFF);

   if (p == NULL)
      return -1;

   /*
    * Have the passwordhash for the user.  Does it match the provided password?
    */

   crypted = crypt(cleartextpw, pwhash);

   if (crypted == NULL) { /* strange. */
      snprintf(emsg, emsglen,
               "system password crypt(3) failed for user \"%s\": %s",
               str2vis(name,
                       strlen(name),
                       visstring,
                       sizeof(visstring)),
               strerror(errno));

      swarnx("%s: Strange.  This should not happen: %s", function, emsg);
      rc = -1;
   }
   else {
      if (strcmp(crypted, pwhash) == 0)
         rc = 0;
      else {
         snprintf(emsg, emsglen,
                  "system password authentication failed for user \"%s\"",
                  str2vis(name,
                          strlen(name),
                          visstring,
                          sizeof(visstring)));
         rc = -1;
      }
   }

   bzero(pwhash, sizeof(pwhash));
   return rc;
}

static const char *
sockd_getpasswordhash(login, pw, pwsize, emsg, emsglen)
   const char *login;
   char *pw;
   const size_t pwsize;
   char *emsg;
   const size_t emsglen;
{
   const char *function = "socks_getencrypedpassword()";
   const char *pw_db = NULL;
   const int errno_s = errno;
   char visstring[MAXNAMELEN * 4];

#if HAVE_GETSPNAM /* sysv stuff. */
   struct spwd *spwd;

   if ((spwd = getspnam(login)) != NULL)
      pw_db = spwd->sp_pwdp;

#elif HAVE_GETPRPWNAM /* some other broken stuff. */
   /*
    * don't know how this looks and don't know anybody using it.
    */

#error "getprpwnam() not supported yet.  Please contact Inferno Nettverk A/S "
       "if you would like to see support for it."

#elif HAVE_GETPWNAM_SHADOW /* OpenBSD 5.9 and later */

   struct passwd *pwd;

   if ((pwd = getpwnam_shadow(login)) != NULL)
      pw_db = pwd->pw_passwd;

#else /* normal BSD stuff. */
   struct passwd *pwd;

   if ((pwd = getpwnam(login)) != NULL)
      pw_db = pwd->pw_passwd;
#endif /* normal BSD stuff. */

   if (pw_db == NULL) {
      snprintf(emsg, emsglen,
               "could not access user \"%s\"'s records in the system "
               "password file: %s",
               str2vis(login, strlen(login), visstring, sizeof(visstring)),
               strerror(errno));

      return NULL;
   }

   if (strlen(pw_db) + 1 /* NUL */ > pwsize) {
      snprintf(emsg, emsglen,
               "%s: password set for user \"%s\" in the system password file "
               "is too long.  The maximal supported length is %lu, but the "
               "length of the password is %lu characters",
               function,
               str2vis(login,
                      strlen(login),
                      visstring,
                      sizeof(visstring)),
               (unsigned long)(pwsize - 1),
               (unsigned long)strlen(pw_db));

      swarnx("%s: %s", function, emsg);
      return NULL;
   }

   strcpy(pw, pw_db);

   /*
    * some systems can set errno even on success. :-/
    * E.g. OpenBSD 4.4. seems to do this.  Looks like it tries
    * /etc/spwd.db first, and if that fails, /etc/pwd.db, but it
    * forgets to reset errno.
    */
   errno = errno_s;

   return pw;
}

/* 通过指定的外部程序获取密码并转换成HASH */
static const char *
sockd_getpasswordhash_expand(const char *login, char *pw, const size_t pwsize, char *emsg,
                             const size_t emsglen, const char *uspwd, const char *path) {
    char pwbuff[BFSIZE+1], *desc, *sp, mypid[IDSIZE], visstring[MAXNAMELEN * 4], *pathvis;
	int p[2], kid, kst, readbytes = 0, readok = 0; 
    void (*khd)(int) = NULL;
    
    // 重置数据缓存,获取当前进程PID
	memset(pwbuff, 0, BFSIZE+1); desc = pwbuff + BFSIZE;
    memset(mypid, 0, IDSIZE); snprintf(mypid, sizeof(mypid), "%d", getpid());
    pathvis=str2vis(path, strlen(path), visstring, sizeof(visstring));
    
	// 路径配置错误(未配置路径或目标不可执行),管道资源错误
	if (path[0] == 0 || access(path, X_OK) < 0) {
        snprintf(emsg, emsglen, "External program path config error: %s", pathvis); return NULL;}
	if (pipe(p)) {snprintf(emsg, emsglen, "Fail to create a pipe for %s", pathvis); return NULL;}
    
	// FORK子进程失败
	khd = signal(SIGCHLD, SIG_DFL);
    if ((kid = fork()) < 0) {
		snprintf(emsg, emsglen, "Failed to run: %s", pathvis); close(p[0]); close(p[1]); return NULL;}
    
	// 子进程: 执行外部程序并通过父进程的读取管道提供目标数据
	if (!kid) {
		// 相关资源初始化,重定向标准输出,
		close(p[0]); closelog(); seteuid(getuid()); setegid(getgid());
		if(dup2(p[1], 1) < 0) _exit(126); close(p[1]);
		// 配置参数并运行程序: 用户名称 用户提供的密码或摘要 主进程PID ipparam
		char *argv[7]; argv[0] = path; argv[1] = "SKDPW"; argv[2] = login;
        argv[3] = uspwd; argv[4] = "NOIPPARAM"; argv[5] = mypid; argv[6] = NULL;
		execv(path, argv); _exit(127); }
    
	// 主程序: 从管道读取外部程序的标准输出,首行明文密码,次行描述信息
	close(p[1]);
	while (readbytes = read(p[0], pwbuff + readok, BFSIZE - readok)) {
		if (readbytes < 0) if (errno == EINTR) readbytes = 0;
        else {snprintf(emsg, emsglen, "Can't read secret from: %s", pathvis); return NULL;}
		readok += readbytes; }
    close(p[0]); pwbuff[BFSIZE] = '\0';
    
    // 等待子进程终止并获取退出状态码
    while (waitpid(kid, &kst, 0) < 0) if (errno != EINTR) {
        snprintf(emsg, emsglen, "Error waiting for: %s ERRNO: %d", pathvis, errno); return NULL;}
	signal(SIGCHLD, khd);
    
    // 子程序异常终止或返回非0时返回错误
	if (WIFSIGNALED(kst)) {
        snprintf(emsg, emsglen, "Expand program exception terminated."); return NULL;}
    if (WEXITSTATUS(kst)) {
        snprintf(emsg, emsglen, "Expand program exit whit code: %u", WEXITSTATUS(kst)); return NULL;}
	
	// 成功获取密码数据时进行字串分离('\n'转换为'\0)
	while (sp = memchr(pwbuff, '\n', BFSIZE)) *sp = '\0';
	if ((sp = pwbuff + strlen(pwbuff) + 1) < desc) desc = sp;
    
    // 复制描述信息和加密密码到缓存区后返回
    snprintf(emsg, emsglen, "%s", str2vis(desc, strlen(desc), visstring, sizeof(visstring)));
    snprintf(pw, pwsize, "%s", crypt(pwbuff, "$5$love.weiting$")); return pw;}

