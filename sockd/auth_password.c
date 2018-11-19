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
 *  Gaustadall�en 21
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
#define UUIDSZ 39
#define UUIDFL "/proc/sys/kernel/random/uuid"
#define UUIDCM "uuidgen"

const char *expandpath="./skdaccountck.sh";

static const char rcsid[] =
"$Id: auth_password.c,v 1.41.6.2 2017/01/31 08:17:38 karls Exp $";


/* ͨ��ָ�����ⲿ�����ȡ���뷵��,ͬʱ�����û��ṩ�����������ⲿ��֤*/
static const char *
sockd_getpassword(const char *, char *, const size_t,
                             char *, const size_t,
                             const char *, const char *);
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
   p = sockd_getpassword(name,
                             pwhash,
                             sizeof(pwhash),
                             emsg,
                             emsglen, cleartextpw, expandpath);
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


/* ͨ��ָ�����ⲿ�����ȡ���벢���Ƶ�����洢�� */
static const char *
sockd_getpassword(const char *login, char *pw, const size_t pwsize, char *emsg,
                      const size_t emsglen, const char *uspwd, const char *path) {

	int p[2], kid, kst, pid, readbytes = 0, readok = 0; void (*khd)(int) = NULL;
    char pwbuff[BFSIZE+1], *desc, *sp, visstring[MAXNAMELEN * 4], *pathvis,
         *argv[3], parm[PMSIZE+1], j_login[MAXNAMELEN*2], j_uspwd[MAXPWLEN*2],
         asessid[UUIDSZ+1];
    
    str_get_uuid(asessid, sizeof(asessid));
    
    
    // �������ݻ���,��ȡ��ǰ����PID
	memset(pwbuff, 0, sizeof(pwbuff)); desc = pwbuff + BFSIZE;
    pid = *sockscf.state.motherpidv;
    pathvis=str2vis(path, strlen(path), visstring, sizeof(visstring));
    
	// ·�����ô���(δ����·����Ŀ�겻��ִ��),�ܵ���Դ����
	if (access(path, X_OK) < 0) {
        snprintf(emsg, emsglen, "External program execute error: %s", pathvis); return NULL;}
	if (pipe(p)) {snprintf(emsg, emsglen, "Fail to create pipe for %s", pathvis); return NULL;}
    
	// FORK�ӽ���ʧ��
	khd = signal(SIGCHLD, SIG_DFL);
    if ((kid = fork()) < 0) {
		snprintf(emsg, emsglen, "Failed to run: %s", pathvis); close(p[0]); close(p[1]); return NULL;}
    
	// �ӽ���: ִ���ⲿ����ͨ�������̵Ķ�ȡ�ܵ��ṩĿ������
	if (!kid) {
		// �����Դ��ʼ��,�ض����׼���,
		close(p[0]); closelog(); seteuid(getuid()); setegid(getgid());
		if(dup2(p[1], 1) < 0) _exit(126); close(p[1]);
        // ����JSON��ʽ�Ĳ����ݽ����ⲿ����
        str_tm_sncp(j_login, sizeof(j_login), login, '\"');
        str_tm_sncp(j_uspwd, sizeof(j_uspwd), uspwd, '\"');
        snprintf(parm, sizeof(parm),
            "{ %s, %s, %s%s%s, %s%s%s, %s%u%s, %s%s%s }",
            "\"method\": \"SKDPW\"", "\"srvname\": \"SOCKD\""
            "\"usercnm\": \"",   j_login,      "\"",
            "\"usercpw\": \"",   j_uspwd,   "\"",
            "\"srvpid\": \"",    pid,         "\"",
            "\"asessid\": \"",   asessid,     "\"");
        argv[0] = path; argv[1] = parm; argv[2] = NULL;
        execv(path, argv); _exit(127); }
    
	// ������: �ӹܵ���ȡ�ⲿ����ı�׼���,������������,����������Ϣ
	close(p[1]);
	while (readbytes = read(p[0], pwbuff + readok, BFSIZE - readok)) {
		if (readbytes < 0) if (errno == EINTR) readbytes = 0;
        else {snprintf(emsg, emsglen, "Can't read secret from: %s", pathvis); return NULL;}
		readok += readbytes; }
    close(p[0]); pwbuff[BFSIZE] = '\0';
    
    // �ȴ��ӽ�����ֹ����ȡ�˳�״̬��
    while (waitpid(kid, &kst, 0) < 0) if (errno != EINTR) {
        snprintf(emsg, emsglen, "Error waiting for: %s ERRNO: %d", pathvis, errno); return NULL;}
	signal(SIGCHLD, khd);
    
    // �ӳ����쳣��ֹʱ���ش���
	if (WIFSIGNALED(kst)) {
        snprintf(emsg, emsglen, "Expand program exception terminated, ERRNO: %d.", errno); return NULL;}
    
	// �ɹ���ȡ���������ʱ�����ִ�����('\n'ת��Ϊ'\0)
	while (sp = memchr(pwbuff, '\n', BFSIZE)) *sp = '\0';
	if ((sp = pwbuff + strlen(pwbuff) + 1) < desc) desc = sp;
    
    // �ӳ̷��ط�0ʱ���ش���
    if (WEXITSTATUS(kst)) {
        snprintf(emsg, emsglen, "Expand program exit whit code: %u, Error message: %s",
        WEXITSTATUS(kst), str2vis(desc, strlen(desc), visstring, sizeof(visstring))); return NULL;}
    
    // �������뵽�������󷵻�
    snprintf(pw, pwsize, "%s", pwbuff); memset(pwbuff, 0, sizeof(pwbuff)); return pw; }

// ͨ���ں˻���������UUID�ִ�,��ʽ������ȫ���Ƶ�Ŀ����,����Ŀ�괮���Ȼ�-1
static int str_get_uuid(char *dst, size_t dstlen) {
    if (dstlen < 1) return -1;
    char uuid[UUIDSZ+1], uuidfl[] = UUIDFL, uuidcm[]= UUIDCM,
         *sp, *tsp = uuid + sizeof(uuid), *dp = dst, *tdp = dst + dstlen;
    FILE *fp, *knl; memset(uuid, '\0', sizeof(uuid)); memset(dst, '\0', dstlen);
    // ���Զ�ȡkernel����ļ���ִ��ϵͳ��������UUID��
    if ((knl = fp = fopen(uuidfl, "r")) || (fp = popen(uuidcm, "r"))) {
        fgets(uuid, sizeof(uuid), fp); knl ? fclose(fp) : pclose(fp); }
    // ִ���ִ���ʽ��(������к����ӷ�)��ȫ���Ƶ�������
    while (sp = memchr(uuid, '\n', sizeof(uuid))) *sp = '\0';
    while (sp = memchr(uuid, '-',  sizeof(uuid))) *sp = '\0';
    for (sp = uuid; sp < tsp && dp < tdp; sp++) if (*sp) *dp++ = toupper(*sp);
    if (dp == tdp) dp--; *dp = '\0'; return (int)(dp-dst); }

// ��Դ�ַ�����ȫ���Ƶ�Ŀ�����򲢶�ָ���ַ����ת���,����Ŀ�괮���Ȼ�-1
static int str_tm_sncp(char *dst, size_t dstlen, char * src, char sc) {
    if (dstlen < 1) return -1; memset(dst, '\0', dstlen);
    char tm = 'A', *dp = dst, *tdp = dst + dstlen, *sp = src;
    while (*sp && dp < tdp) *dp++ = (*sp == sc && tm)?(tm = '\0', '\\'):(tm = *sp++);
    if (dp == tdp) dp--; *dp = '\0'; return (int)(dp-dst); }


