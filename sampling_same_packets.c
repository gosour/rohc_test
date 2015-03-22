/*
 * Copyright 2011,2012,2013,2014 Didier Barvaux
 * Copyright 2010,2012 Viveris Technologies
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
 
/**
 * @file     rohc_hello_world.c
 * @brief    A program that uses the compression part of the ROHC library
 * @author   Didier Barvaux <didier@barvaux.org>
 * @author   Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 *
 * A program to learn how to use the ROHC library.
 *
 * Build with:
 *   gcc -o rohc_hello_world -Wall \
 *      $(pkg-config rohc --cflags) \
 *      rohc_hello_world.c \
 *      $(pkg-config rohc --libs)
 *
 * API documentation:
 *   http://rohc-lib.org/support/documentation/#library-api
 *
 * Tutorials:
 *   http://rohc-lib.org/support/wiki/
 *
 * Mailing list:
 *   http://rohc-lib.org/support/mailing-list/
 */
 
#include <stdio.h>  /* for the printf() function */
 
/* includes required to create a fake IP packet */
#include <netinet/ip.h>  /* for the IPv4 header */
#include <string.h>      /* for the strlen() */
#include <rohc/rohc_buf.h>  /* for the rohc_buf_*() functions */
 
/* includes required to use the compression part of the ROHC library */
#include <time.h>             /* required by time() */
#include <rohc/rohc_comp.h>   /* for rohc_comp_*() functions */
 
/* The size (in bytes) of the buffers used in the program */
#define BUFFER_SIZE 2048
 
/* The payload for the fake IP packet */
#define FAKE_PAYLOAD "hello, ROHC world!"
 
#define PACKET_COUNT 100
/* return a random number	 every time it is called */
static int gen_random_num(const struct rohc_comp *const comp,
                          void *const user_context)
{
   return rand();
}
 
/* The main entry point of the program (arguments are not used) */
int main(int argc, char **argv)
{
	/* Create the compressor first*/
   struct rohc_comp *compressor;  /* the ROHC compressor */
   rohc_status_t rohc_status;
   size_t i;
 
   /* print the purpose of the program on the console */
	printf("Analyzing multiple packet compression\n");
 
   /* initialize the random generator with the current time */
   srand(time(NULL));
 
   /* create a ROHC compressor with good default parameters */
   printf("create the ROHC compressor\n");
   compressor = rohc_comp_new2(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX,
                               gen_random_num, NULL);
   if(compressor == NULL)
   {
      fprintf(stderr, "failed create the ROHC compressor\n");
      /* leave with an error code */
      return 1;
   }
 
   /* enable the IP-only compression profile */
   printf("enable the IP-only compression profile\n");
   if(!rohc_comp_enable_profile(compressor, ROHC_PROFILE_IP))
   {
      fprintf(stderr, "failed to enable the IP-only profile\n");
      /* cleanup compressor, then leave with an error code */
      rohc_comp_free(compressor);
      return 1;
   }
 
 	/* Creation of compressor ends here*/
 	
 	/* Generate multiple packets in this section*/
 	int j = 0;
	for(j=0;j<PACKET_COUNT;j++){ 
 		/* the buffer that will contain the IPv4 packet to compress */
	   uint8_t ip_buffer[BUFFER_SIZE];
	   /* the packet that will contain the IPv4 packet to compress */
	   struct rohc_buf ip_packet = rohc_buf_init_empty(ip_buffer, BUFFER_SIZE);
	   /* the header of the IPv4 packet */
	   struct iphdr *ip_header;
	 
	   uint8_t rohc_buffer[BUFFER_SIZE];
	   /* the packet that will contain the resulting ROHC packet */
	   struct rohc_buf rohc_packet = rohc_buf_init_empty(rohc_buffer, BUFFER_SIZE);
  
	   /* create a fake IP packet for the purpose of this simple program */
	   printf("build a fake IP packet\n");
	   ip_header = (struct iphdr *) rohc_buf_data(ip_packet);
	   ip_header->version = 4; /* we create an IP header version 4 */
	   ip_header->ihl = 5; /* min. IPv4 header length (in 32-bit words) */
	   ip_packet.len += ip_header->ihl * 4;
	   ip_header->tos = 0; /* TOS is not important for the example */
	   ip_header->tot_len = htons(ip_packet.len + strlen(FAKE_PAYLOAD));
	   ip_header->id = 0; /* ID is not important for the example */
	   ip_header->frag_off = 0; /* No packet fragmentation */
	   ip_header->ttl = 1; /* TTL is not important for the example */
	   ip_header->protocol = 134; /* protocol number */
	   ip_header->check = 0x3fa9; /* checksum */
	   ip_header->saddr = htonl(0x01020304); /* source address 1.2.3.4 */
	   ip_header->daddr = htonl(0x05060708); /* destination addr. 5.6.7.8 */
	 
	   /* copy the payload just after the IP header */
	   rohc_buf_append(&ip_packet, (uint8_t *) FAKE_PAYLOAD, strlen(FAKE_PAYLOAD));
	 
	  	if(j==0)
	  		printf("***Uncompressed Packet Length:\t%d\n",ip_packet.len);
	 
	   rohc_status = rohc_compress4(compressor, ip_packet, &rohc_packet);
	   if(rohc_status != ROHC_STATUS_OK)
	   {
		  fprintf(stderr, "compression of fake IP packet failed: %s (%d)\n",
		          rohc_strerror(rohc_status), rohc_status);
		  /* cleanup compressor, then leave with an error code */
		  rohc_comp_free(compressor);
		  return 1;
	   }
	 
	   printf("***Packet no: %d compressed Packet Length:\t%d\n",j,rohc_packet.len);
	   
		
 	}
   rohc_comp_free(compressor);
 
   /* leave the program with a success code */
   return 0;
}
