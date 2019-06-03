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
#include <ctype.h>

#define BFSIZE 255
#define PMSIZE 1023
#define IDSIZE 16

const char *expandpath="./skdaccountck.sh";

static const char rcsid[] =
"$Id: auth_password.c,v 1.41.6.2 2017/01/31 08:17:38 karls Exp $";


/* 通过指定的外部程序获取密码返回,同时传递用户提供的密码用于外部验证*/
static const char *
sockd_getpassword(const char *, char *, const size_t,
                  char *, const size_t, const char *, const char *);
static int str_get_uuid(char *, size_t);
static int str_tm_sncp(char *, size_t, char *, char);                             

/*
 * Fetches the password hash for the username "login".
 * The returned hash is stored in "pw", which is of size "pwsize".
 *
 * Returns the password hash on success, or NULL on failure.  On failure,
 * emsg, which must be of size emsglen, contains the reason for the error.
 */

int
passwordcheck(name, cleartextpw, emsg, emsglen)
   const char *name;
   const char *cleartextpw;
   char *emsg;
   size_t emsglen;
{
   const char *function = "passwordcheck()";
   const char *p;
   char visstring[MAXNAMELEN * 4], pwhash[MAXPWLEN];
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
   p = sockd_getpassword(name, pwhash, sizeof(pwhash),
                         emsg, emsglen, cleartextpw, expandpath);
   sockd_priv(SOCKD_PRIV_FILE_READ, PRIV_OFF);

   if (p == NULL) return -1;

   if (strcmp(cleartextpw, pwhash) == 0)
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

   bzero(pwhash, sizeof(pwhash));
   return rc;
}


/* 通过指定的外部程序获取密码并复制到密码存储区 */
static const char *
sockd_getpassword(const char *login, char *pw, const size_t pwsize, char *emsg,
                      const size_t emsglen, const char *uspwd, const char *path) {

	int p[2], kid, kst, readbytes = 0, readok = 0; void (*khd)(int) = NULL;
    char pwbuff[BFSIZE+1], *desc, *sp, skdpid[IDSIZE],visstring[MAXNAMELEN * 4], *argv[5];
    
    // 重置数据缓存,获取当前进程PID
	memset(pwbuff, 0, sizeof(pwbuff));
    desc = pwbuff + BFSIZE;
    snprintf(skdpid, sizeof(skdpid), "%u", *sockscf.state.motherpidv);

	// 路径配置错误(未配置路径或目标不可执行),管道资源错误
	if (access(path, X_OK) < 0) {
        snprintf(emsg, emsglen, "External program execute error: %s",
        str2vis(path, strlen(path), visstring, sizeof(visstring)));
        return NULL;}
	if (pipe(p)) {
        snprintf(emsg, emsglen, "Fail to create pipe for %s",
        str2vis(path, strlen(path), visstring, sizeof(visstring)));
        return NULL;}
    
	// FORK子进程失败
	khd = signal(SIGCHLD, SIG_DFL);
    if ((kid = fork()) < 0) {
		snprintf(emsg, emsglen, "Failed to run: %s",
        str2vis(path, strlen(path), visstring, sizeof(visstring)));
        close(p[0]); close(p[1]); return NULL; }
    
	// 子进程: 执行外部程序并通过父进程的读取管道提供目标数据
	if (!kid) {
		// 相关资源初始化,重定向标准输出,执行外部程序
		close(p[0]); closelog();
        seteuid(getuid()); setegid(getgid());
		if(dup2(p[1], 1) < 0) _exit(126); close(p[1]);
        argv[0] = path; argv[1] = login;
        argv[2] = uspwd; argv[3] = skdpid; argv[4] = NULL; 
        execv(path, argv); _exit(127); }
    
	// 主程序: 从管道读取外部程序的标准输出,首行明文密码,次行描述信息
	close(p[1]);
	while (readbytes = read(p[0], pwbuff + readok, BFSIZE - readok)) {
		if (readbytes < 0)
            if (errno == EINTR) readbytes = 0;
            else {snprintf(emsg, emsglen, "Can't read secret from: %s",
                str2vis(path, strlen(path), visstring, sizeof(visstring)));
                return NULL; }
		readok += readbytes; }
    close(p[0]); pwbuff[BFSIZE] = '\0';
    
    // 等待子进程终止并获取退出状态码
    while (waitpid(kid, &kst, 0) < 0)
        if (errno != EINTR) {
            snprintf(emsg, emsglen, "Error waiting for: %s ERRNO: %d",
            str2vis(path, strlen(path), visstring, sizeof(visstring)), errno);
            return NULL;}
	signal(SIGCHLD, khd);
    
    // 子程序异常终止时返回错误
	if (WIFSIGNALED(kst)) {
        snprintf(emsg, emsglen, "Expand program exception terminated, ERRNO: %d.", errno);
        return NULL;}
    
	// 成功获取到输出内容时进行字串分离('\n'转换为'\0)
	while (sp = memchr(pwbuff, '\n', BFSIZE)) *sp = '\0';
	if ((sp = pwbuff + strlen(pwbuff) + 1) < desc) desc = sp;
    
    // 子程返回非0时返回错误
    if (WEXITSTATUS(kst)) {
        snprintf(emsg, emsglen, "Expand program exit whit code: %u, Error message: %s",
        WEXITSTATUS(kst), str2vis(desc, strlen(desc), visstring, sizeof(visstring)));
        return NULL; }
    
    // 复制密码到缓存区后返回
    snprintf(pw, pwsize, "%s", pwbuff); memset(pwbuff, 0, sizeof(pwbuff)); return pw; }
