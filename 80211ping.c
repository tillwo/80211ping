/*
 *  80211ping - "ping" 802.11 stations by sending data frames and wait for ack
 * 
 *  Copyright (C) 2012 Till Wollenberg <till *dot* wollenberg *at* uni-rostock *dot* de>
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */
 
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <net/if.h>
#include <signal.h>
#include <pcap/pcap.h>
#include "endian.h"

/* uclibc's pcap.h misses this definition */
#ifndef PCAP_NETMASK_UNKNOWN
#define PCAP_NETMASK_UNKNOWN    0xffffffff
#endif

typedef struct {
	uint8_t b[6];
} __attribute__((packed)) mac_t;

/* Fixed length part of the radiotap header */
typedef struct {
	uint8_t  version;
	uint8_t  padding;
	uint16_t length;
#define RADIOTAP_PRESENT_RATE   0x00000004
#define RADIOTAP_PRESENT_RETRY  0x00020000
	uint32_t present;
} __attribute__((packed)) hdrrt_t;

typedef struct {
#define TYPE_DATA_NULL 0x48
#define TYPE_CTRL_RTS  0xb4
	uint8_t  type_subtype;
#define FLAG_MOREDATA  0x20
	uint8_t  flags;
	uint16_t duration;
	mac_t    dest;
	mac_t    src;
	mac_t    bssid;
	uint16_t seq;
} __attribute__((packed)) hdr80211_t;

static int terminated;
static pcap_t *pcap;


/*
 * Test if str is a valid MAC address
 * (code taken from BlueZ's lib/bluetooth.c)
 */
static int check_mac(const char *str)
{
	if (!str)
		return -1;

	if (strlen(str) != 17)
		return -1;

	while (*str) {
		if (!isxdigit(*str++))
			return -1;

		if (!isxdigit(*str++))
			return -1;

		if (*str == 0)
			break;

		if (*str++ != ':')
			return -1;
	}

	return 0;
}

/*
 * Convert MAC address given as string to byte array.
 * (code based on BlueZ's lib/bluetooth.c)
 */
static int strtomac(const char *str, mac_t *mac)
{
	int i;

	if (check_mac(str) < 0) {
		memset(mac, 0, sizeof(mac_t));
		return -1;
	}

	for (i = 0; i < 6; i++, str += 3) {
		mac->b[i] = strtol(str, NULL, 16);
	}

	return 0;
}

static void sigint(int sig)
{
	terminated = 1;
	pcap_breakloop(pcap);
}

static void print_usage()
{
#define STRINGIFY_HELPER(x) #x
#define STRINGIFY(x) STRINGIFY_HELPER(x)
	fprintf(stderr,
		"80211ping " STRINGIFY(VERSION) "\n"
		"Usage:\n"
		" 80211ping <options> <destination>\n"
		"  -I <device>    device to use (mandatory, device must be in monitor mode)\n"
		"  -c <count>     stop after sending <count> packets (default: don't stop)\n"
		"  -i <interval>  send packet each <interval> ms (default: 1000 ms)\n"
		"  -r <rate>      specify data rate (in Mbit/s, not supported by all drivers)\n"
		"  -m             set \"more data\" flag\n"
	);
}

static void packet_handler(u_char *user, const struct pcap_pkthdr *hdr, const u_char *packet)
{
	int *acks = (int*)user;
	(*acks)++;
}

static void sigalrm(int sig)
{
	pcap_breakloop(pcap);
}

int main (int argc, char *argv[])
{
	char ifname[IFNAMSIZ];
	int count;
	int interval;
	int rate;
	int moredata;
	mac_t source;
	mac_t dest;
	char dest_str[18];
	int c;
	char errbuf[PCAP_ERRBUF_SIZE];
	char filter[256];
	struct bpf_program fp;
	int linktype;
	uint8_t packet[256];
	int packet_length;
	hdrrt_t* const hdrrt = (hdrrt_t*)packet;
	uint32_t present;
	int rtlen;
	hdr80211_t *hdr80211;
	struct itimerval itv;
	volatile int acks;
	int packets_sent;
	int packets_acked;
	struct timeval tv;
	
	gettimeofday(&tv, NULL);
	srand(tv.tv_usec * tv.tv_sec); 
	
	/*
	 * Default values
	 */
	ifname[0] = '\0';
	count = -1;         /* -1 == infinite loop */
	interval = 1000000; /* microseconds */
	rate = -1;          /* -1 == don't specify rate to mac80211 */
	moredata = 0;
	
	
	/*
	 * Parse command line arguments
	 */
	opterr = 0;
	while ((c = getopt(argc, argv, ":I:c:i:r:m")) != -1) {
		switch (c) {
			case 'I':
				if (strlen(optarg) < IFNAMSIZ) {
					strncpy(ifname, optarg, IFNAMSIZ);
				}
				else {
					fprintf(stderr, "'%s' is not a valid interface name\n", optarg);
					return -1;
				}
				break;

			case 'i':
				interval = (strtof(optarg, NULL) * 1000000);
				if (interval <= 0) {
					fprintf(stderr, "Interval must be greater than 0.\n");
					return -1;
				}
				break;

			case 'c':
				count = strtol(optarg, NULL, 10);
				if (count <= 0) {
					fprintf(stderr, "Count must be greater than 0.\n");
					return -1;
				}
				break;
			
			case 'r':
				rate = (strtof(optarg, NULL) * 2);
				if (rate <= 2) {
					fprintf(stderr, "Data rate must be greater than 1 Mbit/s.\n");
					return -1;
				}
				break;		

			case 'm':
				moredata = 1;
				break;	
								
			case ':':
				fprintf(stderr, "Option -%c requires an argument.\n", optopt);
				print_usage();
				return -1;
				
			case '?':
				fprintf(stderr, "Invalid option: -%c\n", optopt);
				print_usage();
				return -1;
				
			default:
				abort();
		}
	}     
	
	if (optind < argc) {
		if (strtomac(argv[optind], &dest) < 0) {
			fprintf(stderr, "'%s' is not a valid MAC address.\n", argv[optind]);
			return -1;
		}
	}
	else {
		fprintf(stderr, "No destination specified.\n");
		print_usage();
		return -1;
	}
	
	if (strlen(ifname) == 0) {
		fprintf(stderr, "You have to specify which interface to use (see -I option).\n");
		return -1;
	}
	
	sprintf(dest_str, "%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X", 
		dest.b[0], dest.b[1], dest.b[2], dest.b[3], dest.b[4], dest.b[5]);
	
	/*
	 * Create random source MAC address
	 */
	
	/* TODO: Maybe deriving the source MAC address from the actual MAC address of the
	         device used would be better. */
	
	source.b[0] = (rand() & 0xFE) | 0x02; /* unicast + locally administered */
	source.b[1] = rand();
	source.b[2] = rand();
	source.b[3] = rand();
	source.b[4] = rand();
	source.b[5] = rand();
	
	
	/*
	 * PCAP initialization
	 */
	errbuf[0] = '\0';
	pcap = pcap_open_live(ifname, 80, 1, 0, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "Unable to open interface: %s\n", errbuf);
		return 1;
	}
	
	linktype = pcap_datalink(pcap);
	if (linktype != DLT_IEEE802_11_RADIO) {
		fprintf(stderr, "Unsupported link type (%s) on %s, terminating.\n",
		                pcap_datalink_val_to_name(linktype), ifname);
		pcap_close(pcap);
		return 1;
	}

	/* Build filter that matches only ACKs sent to our fake address */
	snprintf(filter, sizeof(filter), "link[0]=0xd4 and link[4]=0x%2.2x and "
	        "link[5]=0x%2.2x and link[6]=0x%2.2x and link[7]=0x%2.2x and "
	        "link[8]=0x%2.2x and link[9]=0x%2.2x", source.b[0], source.b[1],
	         source.b[2], source.b[3], source.b[4], source.b[5]);

	if (pcap_compile(pcap, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) < 0) {
		fprintf(stderr, "Error compiling the pcap filter: %s.\n", pcap_geterr(pcap));
		return 1;
	}
	
	if (pcap_setfilter(pcap, &fp) < 0) {
		fprintf(stderr, "Error setting pcap filter: %s.\n", pcap_geterr(pcap));
		return 1;
	}
	
	/*
	 * Craft "ping" frame (acutally a 802.11 NULL DATA frame)
	 */
	
	/* set-up basic radiotap header */
	rtlen = 8;
	hdrrt->version = 0;
	hdrrt->padding = 0;
	present = 0;
	
	/* Add fields to radiotap header: data rate field (if requested by user) */
	if (rate != -1) {
		packet[rtlen] = rate;
		present |= RADIOTAP_PRESENT_RATE;
		rtlen++;
	}
	
	/* Add fields to radiotap header: retry count */
	packet[rtlen] = 0;
	present |= RADIOTAP_PRESENT_RETRY;
	rtlen++;

	/* Finalize radiotap header and build 802.11 frame header */	
	hdrrt->length = htole16(rtlen);
	hdrrt->present = htole32(present);
	hdr80211 = (hdr80211_t*)&packet[rtlen];
	
	hdr80211->type_subtype = TYPE_DATA_NULL;
	hdr80211->flags = 0;
	if (moredata) {
		hdr80211->flags |= FLAG_MOREDATA;
	}
	hdr80211->duration = 0;
	memcpy(&hdr80211->dest, &dest, sizeof(dest));
	memcpy(&hdr80211->src, &source.b, 6);
	memcpy(&hdr80211->bssid, &source.b, 6);
	
	/* "ping" frame complete */
	packet_length = sizeof(hdr80211_t) + rtlen;
	
	
	/*
	 * Main loop: periodically send crafted frame and watch out for ACKs
	 */
	printf("Sending null data frames from %2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X "
	       "to %s every %.2fs", source.b[0], source.b[1], source.b[2], 
	       source.b[3], source.b[4], source.b[5], dest_str, interval / 1000000.0);
	if (rate != -1) {
		printf(" at %.1fMbit/s", rate / 2.0);
	}
	if (moredata) {
		printf(" (with \"more data\" flag set)");
	}
	printf("...\n");

	terminated = 0;
	signal(SIGINT, sigint);	
	
	signal(SIGALRM, sigalrm);
	
	itv.it_value.tv_sec = (interval / 1000000);
	itv.it_value.tv_usec = (interval % 1000000);
	itv.it_interval.tv_sec = 0;  /* no automatic restart of timer upon */
	itv.it_interval.tv_usec = 0; /* expiration, we restart it manually */
	
	packets_sent = 0;
	packets_acked = 0;
	
	while (!terminated) {
		printf("Sending frame to %s: ", dest_str);
		fflush(stdout);
		
		if (setitimer(ITIMER_REAL, &itv, NULL) != 0) {
			fprintf(stderr, "setitimer() failed (%s)\n", strerror(errno));
			return -1;
		}
		
		if (pcap_inject(pcap, packet, packet_length) >= 0) {
			packets_sent++;
			
			/* Soak in all ACK frames until timeout occurs (pcap_loop is
			   interrupted by calling pcap_breakloop in sigalrm() */
			acks = 0;

			if (pcap_loop(pcap, 0, packet_handler, (u_char*)&acks) != -2) {
				printf("pcap_loop() error\n");
				break;
			}
			
			if (acks == 0) {
				printf("no reply.\n");
			} else {
				packets_acked++;
				if (acks == 1) {
					printf("reply received!\n");
				}
				else {
					printf("reply received! (%d duplicate ACKs)\n", acks - 1);
				}
			}
		}
		else {
			printf("frame injection failed (%s).\n", pcap_geterr(pcap));
			pause();
		}

		if (count == packets_sent) {
			break;
		}
	}
	
	printf("%d packets sent, %d packets acknowledged (%.1f%%)\n",
	       packets_sent, packets_acked, (packets_sent > 0)?
	       ((packets_acked / (float)packets_sent) * 100) : 0);
	pcap_close(pcap);
	
	return 0;
}


#if 0

/* Example frame structure */
static u8 packet[] = {
	/* Radiotap header */
	0x00,                   /* version */
	0x00,                   /* padding */
	0x0a, 0x00,             /* length, little endian */
	0x04, 0x00, 0x02, 0x00, /* present flags (data rate, retry count) */
	0x30,                   /* rate (12 mbit/s) */
	0x01,                   /* retries (1) */

	/* 802.11 header */
	0x48, 0x00,             /* NULL data type (0x2c), flags all 0 */
	0x00, 0x00,             /* duration */
        0xXX, 0xXX, 0xXX, 0xXX, 0xXX, 0xXX, /* destination address */
	0xYY, 0xYY, 0xYY, 0xYY, 0xYY, 0xYY, /* source address */
	0xZZ, 0xZZ, 0xZZ, 0xZZ, 0xZZ, 0xZZ, /* BSSID */
   
	0x00, 0x00,             /* sequence number, usually overwritten by 802.11 stack or hardware */
	0x00, 0x00, 0x00, 0x00  /* FCS, overwritten by 802.11 stack or hardware */
};

#endif

