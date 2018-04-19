/* This code is copied from https://github.com/iputils/iputils/blob/master/ping.c
 * and ping_common.c
 * omitting lots of pieces with bits copied from both files
 * The aim is to understand how to write a basic ping program using IPPROTO_ICMP
 * as implemented in https://lwn.net/Articles/443051/
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <stdlib.h>

#if BYTE_ORDER == LITTLE_ENDIAN
# define ODDBYTE(v)	(v)
#elif BYTE_ORDER == BIG_ENDIAN
# define ODDBYTE(v)	((unsigned short)(v) << 8)
#else
# define ODDBYTE(v)	htons((unsigned short)(v) << 8)
#endif

char * pr_addr(void *sa, socklen_t salen)
{
	static char buffer[4096] = "";
	static struct sockaddr_storage last_sa = { 0 };
	static socklen_t last_salen = 0;
    char address[128];

	if (salen == last_salen && !memcmp(sa, &last_sa, salen))
		return buffer;

	memcpy(&last_sa, sa, (last_salen = salen));
	getnameinfo(sa, salen, address, sizeof address, NULL, 0, NI_NUMERICHOST);
    snprintf(buffer, sizeof buffer, "%s", address);

	return(buffer);
}


unsigned short
in_cksum(const unsigned short *addr, register int len, unsigned short csum)
{
	register int nleft = len;
	const unsigned short *w = addr;
	register unsigned short answer;
	register int sum = csum;

	/*
	 *  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1)
		sum += ODDBYTE(*(unsigned char *)w); /* le16toh() may be unavailable on old systems */

	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}

int main(int argc, char **argv) {
    int sock, alen;
    struct sockaddr_in source = { .sin_family = AF_INET };
    struct sockaddr_in dst;

    /* We first try to make a UDP connection
     * on port 1025 to the destination host
     * so that we can set the source IP correctly
     */
    memset((char *)&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    /* arv[1] is supposed to be an IP address */
    if (inet_aton(argv[1], &dst.sin_addr) == 0) {
        fprintf(stderr, "The first argument must be an IP address\n");
        exit(1);
    }
    dst.sin_port = htons(1025);
    // Create a socket
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (sock == -1) {
        perror("Error creating socket");
    }
    if (getsockname(sock, (struct sockaddr*)&source, &alen) == -1) {
			perror("getsockname");
			exit(2);
	}
    // Source IP address that's set
    //char *ip = inet_ntoa(source.sin_addr);
    //printf("%s\n", ip);
    
    /* Now we create the packet that we send down the wire
     * Since we use IPPROTO_ICMP, we just have to create the
     * ICMP packet
     */
    int datalen = 56;
    int MAXIPLEN = 60;
    int MAXICMPLEN = 76;
    unsigned char *packet;
    struct icmphdr *icp;
    int ntransmitted = 0;

    int packlen = datalen + MAXIPLEN + MAXICMPLEN;
	if (!(packet = (unsigned char *)malloc((unsigned int)packlen))) {
		fprintf(stderr, "ping: out of memory.\n");
		exit(2);
	}
    icp = (struct icmphdr *)packet;
    /* We are sending a ICMP_ECHO ICMP packet */
	icp->type = ICMP_ECHO;
	icp->code = 0;
	icp->checksum = 0;
	icp->un.echo.sequence = htons(ntransmitted+1);
    /* We don't set the echo.id here since IPPROTO_ICMP does it for us
     * it sets it to the source port
     * pfh.icmph.un.echo.id = inet->inet_sport;
     */

    /* compute ICMP checksum here */
    int cc = datalen + 8;
	icp->checksum = in_cksum((unsigned short *)icp, cc, 0);

    /* send the ICMP packet*/
    int i = sendto(sock, icp, cc, 0, (struct sockaddr*)&dst, sizeof(dst));
    printf("Sent %d bytes\n", i);

    /* We have sent the packet, time to attempt to read
     * the reply
     * */
    struct msghdr msg;
    int polling;
    char addrbuf[128];
    struct iovec iov;

    iov.iov_base = (char *) packet;
    iov.iov_len = packlen;

    memset(&msg, 0, sizeof(msg));

    /* check recvmsg() to understand the reasoning/meaning
     * for the different fields
     */
    msg.msg_name = addrbuf;
    msg.msg_namelen = sizeof(addrbuf);
    /* Learn more: 
     * https://www.safaribooksonline.com/library/view/linux-system-programming/9781449341527/ch04.html
     */
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    /* We do a blocking wait here */
    polling = MSG_WAITALL;
    /* check the man page for recvmsg to understand why we need
     * to pass msg here
     * TLDR: passing msg here allows us to check the source
     * address for the unconnected socket, sock
    */
    cc = recvmsg(sock, &msg, polling);
    if (cc  < 0 ){
        perror("Error in recvmsg");
        exit(1);
    }
    __u8 *buf = msg.msg_iov->iov_base;
    struct icmphdr *icp_reply;
    int csfailed;
    icp_reply = (struct icmphdr *)buf;
    csfailed = in_cksum((unsigned short *)icp_reply, cc, 0);
    if (csfailed) {
        printf("(BAD CHECKSUM)");
        exit(1);
    }

    /* Note that we don't have to check the reply ID to match that whether
     * the reply is for us or not, since we are using IPPROTO_ICMP.
     * See https://lwn.net/Articles/443051/ ping_v4_lookup()
     * If we were using a RAW socket, we would need to do that.
     * */
    struct sockaddr_in *from = msg.msg_name;
    if (icp_reply->type == ICMP_ECHOREPLY) {
           printf("%s\n", pr_addr(from, sizeof *from));
           printf("Reply of %d bytes received\n", cc);
           printf("icmp_seq = %u\n", ntohs(icp_reply->un.echo.sequence));
    } else {
        printf("Not a ICMP_ECHOREPLY\n");
    }
    return 0;
}
