#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <net/tcp.h>
#include <net/ip.h>

/*
 * The number of entries that will be pre-loaded into iTable
 * Default: 0
 */
#define exist_iTable_num 0

/*
 * The length of cTable
 */
#define cTable_num 128	

/*
 * The space required for storing one capability
 */
#define capability_len 60	

/*
 * The maximum number of distinct capabilities to send
 */
#define Th_cap 128

/*
 * The detection period
 * 250 equals one second
 */
#define detection_period 1000

/*
 * The time allowed for capability feedback 
 * Default: one second 
 */
#define Th_rtt 250

/*
 * Historical loss rate weight
 */
#define beta 80

/*
 * Kernel does not supporting floating. So increae the floating number by 100 times. 
 */
#define LLR_thres 5 // floating
#define SLR_thres 5 // floating


/*
 * Control variables 
 */
// whether perform UDP encapsulation or not
int IP_in_UDP_ENCAP = 0; 

// If you did have separate machines for senders and mboxes, please set this control variable to 1. Otherwise, if you combine sender and mbox together in one box, please disable this variable.  
int redirect_enabled = 0; 

// This variable is for debugging. Enable it to test the full functionality of MiddlePolice.
int Add_Trim_Capability = 1;

/*
 * Global variables
 */
char mbox_ip[15] = "192.168.1.174";
char victim_ip[15] = "192.168.2.253";
unsigned int mbox_networkip = 0;
unsigned int victim_networkip = 0;

static spinlock_t mylock;
static struct nf_hook_ops nf_hook_out;
static struct nf_hook_ops nf_hook_in;
unsigned int SLR_loss_rate = 0;

struct capability{
    unsigned int id; // capability ID
    unsigned int saddr;	// the source address of the sender	
    unsigned long timestamp; // the time when a packet arrived at the mbox
    char code[capability_len - 16]; // MAC
};


struct cTable{
    struct capability item[cTable_num]; 
    unsigned long start; // Begin to load the cTable 
    unsigned long stop; // start + Th_rtt
    unsigned int n; // The number of capability in the cTable
    unsigned int m; // The number of received capability feedback
};


struct iTable{
    unsigned int f; // Source identifier
    unsigned long TA; // The start time of the current detection period
    unsigned int PID; // Capability ID
    unsigned long NR; // The number of received packets from NR
    unsigned int ND; // The number of dropped packets from f by mbox
    unsigned int WR; // The number of privileged packets allowed for f
    char WV[128]; // For computing the packet loss rates
    unsigned long LR; // Historical loss rates
    unsigned int i; // Experimentally used: count the number of received packets
    struct iTable *next;
};


struct iTable *iTable_header = NULL;
struct iTable *iTable_tail = NULL;


struct cTable c;
struct cTable *ctab = &c;
unsigned int load_cTable = 0;


void initialcTable(struct cTable *p){
    p->n = 0;
    p->start = 0;
    p->stop = 0;
    p->m = 0;

}


unsigned int insertcTable(struct cTable *p, unsigned int saddr, unsigned int id, unsigned long time, char * code){
    unsigned int j = p->n;
    if(j <= (cTable_num - 1)){
	p->item[j].saddr = saddr;
	p->item[j].id = id;
	p->item[j].timestamp = time;
	memcpy(p->item[j].code, code, capability_len - 16);
	(p->n)++;
	//printk(KERN_INFO "cTab insert %u capabilities <NO. %u>\n", id, p->n);
	return p->n;

    }else{
	return 0;
    }
}



void beginToTime(struct cTable *p){
    p->start = jiffies;
    p->stop = jiffies + Th_rtt;

}


unsigned int cTableContainCapability(struct cTable *p, unsigned int id, unsigned int saddr, unsigned long time, char * code){
    unsigned int i = 0;
    while(i < p->n ){
	if( (p->item[i].id == id) && (p->item[i].saddr == saddr) && (p->item[i].timestamp == time)){
	    break;
	}
	i++;

    }		
    if(i < p->n) {

	return 1;

    } else {

	return 0;
    }
}

/*
 * Compute SLR 
 */
void computeSLR(struct cTable *p, unsigned int id, unsigned int saddr, unsigned long time, char * code){
    // Continue to load cTable
    if(p->n < cTable_num){

	// refresh stop time until cTable is Full
	if (cTableContainCapability(p, id, saddr, time, code)) {
	    (p->m)++;
	    if(jiffies > p->stop){
		p->stop = jiffies + 250;
	    }
            //printk(KERN_INFO "NOT FILL UP cTable: Ctab check id %u capabilities <Total checked %u>\n", id, p->m);
	}

    } else if(jiffies <= p->stop) {
	if (cTableContainCapability(p, id, saddr, time, code)){
	    (p->m)++;
	    //printk(KERN_INFO "Ctab check id %u capabilities <Total checked %u>\n", id, p->m);
	}
    } else {
	// compute SLR
        if(load_cTable != 0 && p->n == cTable_num){
	    printk(KERN_INFO "cTable###send %u capabilities receive %u capabilities at this interval.\n", p->n, p->m);
	    if (p->n > p->m) SLR_loss_rate = 100 * (p->n - p->m) / p->n;
	    else SLR_loss_rate = 0;

	    printk(KERN_INFO "SLR %u \n", SLR_loss_rate);

	    // clear cTable
      	    load_cTable = 0;
	}
    }
}

struct iTable *searchiTable(unsigned int addr){

    struct iTable * t = iTable_header;
    while((t != NULL) && (t->f != addr)){
	t = t->next;
    }

    return t;

}


unsigned int ip_str_to_num(const char *buf)
{

    unsigned int tmpip[4] = {0};

    unsigned int tmpip32 = 0; 

    sscanf(buf, "%d.%d.%d.%d", &tmpip[0], &tmpip[1], &tmpip[2], &tmpip[3]);

    tmpip32 = (tmpip[3]<<24) | (tmpip[2]<<16) | (tmpip[1]<<8) | tmpip[0];

    return tmpip32;

}


unsigned int insertiTable(unsigned int srcaddr){

    struct iTable *temp = NULL;
    if ((temp = kmalloc(sizeof(struct iTable), GFP_KERNEL)) != NULL){
	printk(KERN_INFO "insertiTable===>kmalloc and create one new iTable for one new client:%u\n", srcaddr);
	temp->f = srcaddr;
	temp->TA = jiffies;
	temp->PID = 0;
	temp->NR = 0;
	temp->ND = 0;
	temp->WR = 0;				
	memset(temp->WV, 0, 128);
	temp->LR = 0;				
	temp->next = NULL;
    }else{
	printk(KERN_INFO "create one new iTable fail\n");	
	return 0;
    }

    if (iTable_header == NULL){
	iTable_header = temp;
	iTable_tail = temp;

    }else{

	iTable_tail->next = temp;
	iTable_tail = temp;
    }

    return 1;

}

/*AES related Code*/

// Enable both ECB and CBC mode. Note this can be done before including aes.h or at compile-time.
// E.g. with GCC by using the -D flag: gcc -c aes.c -DCBC=0 -DECB=1
#define CBC 1
#define ECB 1

//#include "aes.h"

#ifndef _AES_H_
#define _AES_H_

//#include <stdint.h>


#ifndef CBC
#define CBC 1
#endif

#ifndef ECB
#define ECB 1
#endif



#if defined(ECB) && ECB

void AES128_ECB_encrypt(uint8_t* input, const uint8_t* key, uint8_t *output);
void AES128_ECB_decrypt(uint8_t* input, const uint8_t* key, uint8_t *output);

#endif // #if defined(ECB) && ECB


#if defined(CBC) && CBC

void AES128_CBC_encrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv);
void AES128_CBC_decrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv);

#endif // #if defined(CBC) && CBC



#endif //_AES_H_



/*****************************************************************************/
/* Defines:                                                                  */
/*****************************************************************************/
// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define Nb 4
// The number of 32 bit words in a key.
#define Nk 4
// Key length in bytes [128 bit]
#define KEYLEN 16
// The number of rounds in AES Cipher.
#define Nr 10

// jcallan@github points out that declaring Multiply as a function 
// reduces code size considerably with the Keil ARM compiler.
// See this link for more information: https://github.com/kokke/tiny-AES128-C/pull/3
#ifndef MULTIPLY_AS_A_FUNCTION
#define MULTIPLY_AS_A_FUNCTION 0
#endif


/*****************************************************************************/
/* Private variables:                                                        */
/*****************************************************************************/
// state - array holding the intermediate results during decryption.
typedef uint8_t state_t[4][4];
static state_t* state;

// The array that stores the round keys.
static uint8_t RoundKey[176];

// The Key input to the AES Program
static const uint8_t* Key;

#if defined(CBC) && CBC
// Initial Vector used only for CBC mode
static uint8_t* Iv;
#endif

// The lookup-tables are marked const so they can be placed in read-only storage instead of RAM
// The numbers below can be computed dynamically trading ROM for RAM - 
// This can be useful in (embedded) bootloader applications, where ROM is often limited.
static const uint8_t sbox[256] =   {
    //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

static const uint8_t rsbox[256] =
{ 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };


// The round constant word array, Rcon[i], contains the values given by 
// x to th e power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
// Note that i starts at 1, not 0).
static const uint8_t Rcon[255] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb  };

/*End*/



/*Merge AES-CBC Code*/

/*****************************************************************************/
/* Private functions:                                                        */
/*****************************************************************************/
static uint8_t getSBoxValue(uint8_t num)
{
    return sbox[num];
}

static uint8_t getSBoxInvert(uint8_t num)
{
    return rsbox[num];
}

// This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states. 
static void KeyExpansion(void)
{
    uint32_t i, j, k;
    uint8_t tempa[4]; // Used for the column/row operations

    // The first round key is the key itself.
    for(i = 0; i < Nk; ++i)
    {
	RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
	RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
	RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
	RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
    }

    // All other round keys are found from the previous round keys.
    for(; (i < (Nb * (Nr + 1))); ++i)
    {
	for(j = 0; j < 4; ++j)
	{
	    tempa[j]=RoundKey[(i-1) * 4 + j];
	}
	if (i % Nk == 0)
	{
	    // This function rotates the 4 bytes in a word to the left once.
	    // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

	    // Function RotWord()
	    {
		k = tempa[0];
		tempa[0] = tempa[1];
		tempa[1] = tempa[2];
		tempa[2] = tempa[3];
		tempa[3] = k;
	    }

	    // SubWord() is a function that takes a four-byte input word and 
	    // applies the S-box to each of the four bytes to produce an output word.

	    // Function Subword()
	    {
		tempa[0] = getSBoxValue(tempa[0]);
		tempa[1] = getSBoxValue(tempa[1]);
		tempa[2] = getSBoxValue(tempa[2]);
		tempa[3] = getSBoxValue(tempa[3]);
	    }

	    tempa[0] =  tempa[0] ^ Rcon[i/Nk];
	}
	else if (Nk > 6 && i % Nk == 4)
	{
	    // Function Subword()
	    {
		tempa[0] = getSBoxValue(tempa[0]);
		tempa[1] = getSBoxValue(tempa[1]);
		tempa[2] = getSBoxValue(tempa[2]);
		tempa[3] = getSBoxValue(tempa[3]);
	    }
	}
	RoundKey[i * 4 + 0] = RoundKey[(i - Nk) * 4 + 0] ^ tempa[0];
	RoundKey[i * 4 + 1] = RoundKey[(i - Nk) * 4 + 1] ^ tempa[1];
	RoundKey[i * 4 + 2] = RoundKey[(i - Nk) * 4 + 2] ^ tempa[2];
	RoundKey[i * 4 + 3] = RoundKey[(i - Nk) * 4 + 3] ^ tempa[3];
    }
}

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void AddRoundKey(uint8_t round)
{
    uint8_t i,j;
    for(i=0;i<4;++i)
    {
	for(j = 0; j < 4; ++j)
	{
	    (*state)[i][j] ^= RoundKey[round * Nb * 4 + i * Nb + j];
	}
    }
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void SubBytes(void)
{
    uint8_t i, j;
    for(i = 0; i < 4; ++i)
    {
	for(j = 0; j < 4; ++j)
	{
	    (*state)[j][i] = getSBoxValue((*state)[j][i]);
	}
    }
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
static void ShiftRows(void)
{
    uint8_t temp;

    // Rotate first row 1 columns to left  
    temp           = (*state)[0][1];
    (*state)[0][1] = (*state)[1][1];
    (*state)[1][1] = (*state)[2][1];
    (*state)[2][1] = (*state)[3][1];
    (*state)[3][1] = temp;

    // Rotate second row 2 columns to left  
    temp           = (*state)[0][2];
    (*state)[0][2] = (*state)[2][2];
    (*state)[2][2] = temp;

    temp       = (*state)[1][2];
    (*state)[1][2] = (*state)[3][2];
    (*state)[3][2] = temp;

    // Rotate third row 3 columns to left
    temp       = (*state)[0][3];
    (*state)[0][3] = (*state)[3][3];
    (*state)[3][3] = (*state)[2][3];
    (*state)[2][3] = (*state)[1][3];
    (*state)[1][3] = temp;
}

static uint8_t xtime(uint8_t x)
{
    return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

// MixColumns function mixes the columns of the state matrix
static void MixColumns(void)
{
    uint8_t i;
    uint8_t Tmp,Tm,t;
    for(i = 0; i < 4; ++i)
    {  
	t   = (*state)[i][0];
	Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3] ;
	Tm  = (*state)[i][0] ^ (*state)[i][1] ; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp ;
	Tm  = (*state)[i][1] ^ (*state)[i][2] ; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp ;
	Tm  = (*state)[i][2] ^ (*state)[i][3] ; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp ;
	Tm  = (*state)[i][3] ^ t ;        Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp ;
    }
}

// Multiply is used to multiply numbers in the field GF(2^8)
#if MULTIPLY_AS_A_FUNCTION
static uint8_t Multiply(uint8_t x, uint8_t y)
{
    return (((y & 1) * x) ^
	    ((y>>1 & 1) * xtime(x)) ^
	    ((y>>2 & 1) * xtime(xtime(x))) ^
	    ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
	    ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))));
}
#else
#define Multiply(x, y)                                \
    (  ((y & 1) * x) ^                              \
       ((y>>1 & 1) * xtime(x)) ^                       \
       ((y>>2 & 1) * xtime(xtime(x))) ^                \
       ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
       ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \

#endif

// MixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for the inexperienced.
// Please use the references to gain more information.
static void InvMixColumns(void)
{
    int i;
    uint8_t a,b,c,d;
    for(i=0;i<4;++i)
    { 
	a = (*state)[i][0];
	b = (*state)[i][1];
	c = (*state)[i][2];
	d = (*state)[i][3];

	(*state)[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
	(*state)[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
	(*state)[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
	(*state)[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
    }
}


// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void InvSubBytes(void)
{
    uint8_t i,j;
    for(i=0;i<4;++i)
    {
	for(j=0;j<4;++j)
	{
	    (*state)[j][i] = getSBoxInvert((*state)[j][i]);
	}
    }
}

static void InvShiftRows(void)
{
    uint8_t temp;

    // Rotate first row 1 columns to right  
    temp=(*state)[3][1];
    (*state)[3][1]=(*state)[2][1];
    (*state)[2][1]=(*state)[1][1];
    (*state)[1][1]=(*state)[0][1];
    (*state)[0][1]=temp;

    // Rotate second row 2 columns to right 
    temp=(*state)[0][2];
    (*state)[0][2]=(*state)[2][2];
    (*state)[2][2]=temp;

    temp=(*state)[1][2];
    (*state)[1][2]=(*state)[3][2];
    (*state)[3][2]=temp;

    // Rotate third row 3 columns to right
    temp=(*state)[0][3];
    (*state)[0][3]=(*state)[1][3];
    (*state)[1][3]=(*state)[2][3];
    (*state)[2][3]=(*state)[3][3];
    (*state)[3][3]=temp;
}


// Cipher is the main function that encrypts the PlainText.
static void Cipher(void)
{
    uint8_t round = 0;

    // Add the First round key to the state before starting the rounds.
    AddRoundKey(0); 

    // There will be Nr rounds.
    // The first Nr-1 rounds are identical.
    // These Nr-1 rounds are executed in the loop below.
    for(round = 1; round < Nr; ++round)
    {
	SubBytes();
	ShiftRows();
	MixColumns();
	AddRoundKey(round);
    }

    // The last round is given below.
    // The MixColumns function is not here in the last round.
    SubBytes();
    ShiftRows();
    AddRoundKey(Nr);
}

static void InvCipher(void)
{
    uint8_t round=0;

    // Add the First round key to the state before starting the rounds.
    AddRoundKey(Nr); 

    // There will be Nr rounds.
    // The first Nr-1 rounds are identical.
    // These Nr-1 rounds are executed in the loop below.
    for(round=Nr-1;round>0;round--)
    {
	InvShiftRows();
	InvSubBytes();
	AddRoundKey(round);
	InvMixColumns();
    }

    // The last round is given below.
    // The MixColumns function is not here in the last round.
    InvShiftRows();
    InvSubBytes();
    AddRoundKey(0);
}

static void BlockCopy(uint8_t* output, uint8_t* input)
{
    uint8_t i;
    for (i=0;i<KEYLEN;++i)
    {
	output[i] = input[i];
    }
}



/*****************************************************************************/
/* Public functions:                                                         */
/*****************************************************************************/
#if defined(ECB) && ECB


void AES128_ECB_encrypt(uint8_t* input, const uint8_t* key, uint8_t* output)
{
    // Copy input to output, and work in-memory on output
    BlockCopy(output, input);
    state = (state_t*)output;

    Key = key;
    KeyExpansion();

    // The next function call encrypts the PlainText with the Key using AES algorithm.
    Cipher();
}

void AES128_ECB_decrypt(uint8_t* input, const uint8_t* key, uint8_t *output)
{
    // Copy input to output, and work in-memory on output
    BlockCopy(output, input);
    state = (state_t*)output;

    // The KeyExpansion routine must be called before encryption.
    Key = key;
    KeyExpansion();

    InvCipher();
}


#endif // #if defined(ECB) && ECB





#if defined(CBC) && CBC


static void XorWithIv(uint8_t* buf)
{
    uint8_t i;
    for(i = 0; i < KEYLEN; ++i)
    {
	buf[i] ^= Iv[i];
    }
}

void AES128_CBC_encrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv)
{
    uintptr_t i;
    uint8_t remainders = length % KEYLEN; /* Remaining bytes in the last non-full block */

    BlockCopy(output, input);
    state = (state_t*)output;

    // Skip the key expansion if key is passed as 0
    if(0 != key)
    {
	Key = key;
	KeyExpansion();
    }

    if(iv != 0)
    {
	Iv = (uint8_t*)iv;
    }

    for(i = 0; i < length; i += KEYLEN)
    {
	XorWithIv(input);
	BlockCopy(output, input);
	state = (state_t*)output;
	Cipher();
	Iv = output;
	input += KEYLEN;
	output += KEYLEN;
    }

    if(remainders)
    {
	BlockCopy(output, input);
	memset(output + remainders, 0, KEYLEN - remainders); /* add 0-padding */
	state = (state_t*)output;
	Cipher();
    }
}

void AES128_CBC_decrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv)
{
    uintptr_t i;
    uint8_t remainders = length % KEYLEN; /* Remaining bytes in the last non-full block */

    BlockCopy(output, input);
    state = (state_t*)output;

    // Skip the key expansion if key is passed as 0
    if(0 != key)
    {
	Key = key;
	KeyExpansion();
    }

    // If iv is passed as 0, we continue to encrypt without re-setting the Iv
    if(iv != 0)
    {
	Iv = (uint8_t*)iv;
    }

    for(i = 0; i < length; i += KEYLEN)
    {
	BlockCopy(output, input);
	state = (state_t*)output;
	InvCipher();
	XorWithIv(output);
	Iv = input;
	input += KEYLEN;
	output += KEYLEN;
    }

    if(remainders)
    {
	BlockCopy(output, input);
	memset(output+remainders, 0, KEYLEN - remainders); /* add 0-padding */
	state = (state_t*)output;
	InvCipher();
    }
}


#endif // #if defined(CBC) && CBC



static void phex(uint8_t* str);
static void test_encrypt_ecb(void);
static void test_decrypt_ecb(void);
static void test_encrypt_ecb_verbose(void);
static void test_encrypt_cbc(void);
static void test_decrypt_cbc(void);

// prints string as hex
static void phex(uint8_t* str)
{
    unsigned char i;
    for(i = 0; i < 16; ++i){
	//printk(KERN_INFO "%.2x", str[i]);
    }
    //printk(KERN_INFO "\n");
}

static void test_encrypt_ecb_verbose(void)
{
    // Example of more verbose verification

    uint8_t i, buf[64], buf2[64];

    // 128bit key
    uint8_t key[16] =        { (uint8_t) 0x2b, (uint8_t) 0x7e, (uint8_t) 0x15, (uint8_t) 0x16, (uint8_t) 0x28, (uint8_t) 0xae, (uint8_t) 0xd2, (uint8_t) 0xa6, (uint8_t) 0xab, (uint8_t) 0xf7, (uint8_t) 0x15, (uint8_t) 0x88, (uint8_t) 0x09, (uint8_t) 0xcf, (uint8_t) 0x4f, (uint8_t) 0x3c };
    // 512bit text
    uint8_t plain_text[64] = { (uint8_t) 0x6b, (uint8_t) 0xc1, (uint8_t) 0xbe, (uint8_t) 0xe2, (uint8_t) 0x2e, (uint8_t) 0x40, (uint8_t) 0x9f, (uint8_t) 0x96, (uint8_t) 0xe9, (uint8_t) 0x3d, (uint8_t) 0x7e, (uint8_t) 0x11, (uint8_t) 0x73, (uint8_t) 0x93, (uint8_t) 0x17, (uint8_t) 0x2a,
	(uint8_t) 0xae, (uint8_t) 0x2d, (uint8_t) 0x8a, (uint8_t) 0x57, (uint8_t) 0x1e, (uint8_t) 0x03, (uint8_t) 0xac, (uint8_t) 0x9c, (uint8_t) 0x9e, (uint8_t) 0xb7, (uint8_t) 0x6f, (uint8_t) 0xac, (uint8_t) 0x45, (uint8_t) 0xaf, (uint8_t) 0x8e, (uint8_t) 0x51,
	(uint8_t) 0x30, (uint8_t) 0xc8, (uint8_t) 0x1c, (uint8_t) 0x46, (uint8_t) 0xa3, (uint8_t) 0x5c, (uint8_t) 0xe4, (uint8_t) 0x11, (uint8_t) 0xe5, (uint8_t) 0xfb, (uint8_t) 0xc1, (uint8_t) 0x19, (uint8_t) 0x1a, (uint8_t) 0x0a, (uint8_t) 0x52, (uint8_t) 0xef,
	(uint8_t) 0xf6, (uint8_t) 0x9f, (uint8_t) 0x24, (uint8_t) 0x45, (uint8_t) 0xdf, (uint8_t) 0x4f, (uint8_t) 0x9b, (uint8_t) 0x17, (uint8_t) 0xad, (uint8_t) 0x2b, (uint8_t) 0x41, (uint8_t) 0x7b, (uint8_t) 0xe6, (uint8_t) 0x6c, (uint8_t) 0x37, (uint8_t) 0x10 };

    memset(buf, 0, 64);
    memset(buf2, 0, 64);

    // print text to encrypt, key and IV
    //printk(KERN_INFO "ECB encrypt verbose:\n\n");
    //printk(KERN_INFO "plain text:\n");
    for(i = (uint8_t) 0; i < (uint8_t) 4; ++i)
    {
	phex(plain_text + i * (uint8_t) 16);
    }
    //printk(KERN_INFO "\n");

    //printk(KERN_INFO "key:\n");
    phex(key);
    //printk(KERN_INFO "\n");

    // print the resulting cipher as 4 x 16 byte strings
    //printk(KERN_INFO "ciphertext:\n");
    for(i = 0; i < 4; ++i)
    {
	AES128_ECB_encrypt(plain_text + (i*16), key, buf+(i*16));
	phex(buf + (i*16));
    }
    //printk(KERN_INFO "\n");
}


static void test_encrypt_ecb(void)
{
    uint8_t key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t in[]  = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
    uint8_t out[] = {0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97};
    uint8_t buffer[16];

    AES128_ECB_encrypt(in, key, buffer);

    printk(KERN_INFO "ECB decrypt: ");

    if(0 == strncmp((char*) out, (char*) buffer, 16))
    {
	//printk(KERN_INFO "SUCCESS!\n");
    }
    else
    {
	printk(KERN_INFO "FAILURE!\n");
    }
}

static void test_decrypt_cbc(void)
{
    // Example "simulating" a smaller buffer...

    uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    uint8_t in[]  = { 0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
	0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
	0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16, 
	0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7 };
    uint8_t out[] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
	0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
	0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
	0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };
    uint8_t buffer[64];

    AES128_CBC_decrypt_buffer(buffer+0, in+0,  16, key, iv);
    AES128_CBC_decrypt_buffer(buffer+16, in+16, 16, 0, 0);
    AES128_CBC_decrypt_buffer(buffer+32, in+32, 16, 0, 0);
    AES128_CBC_decrypt_buffer(buffer+48, in+48, 16, 0, 0);

    //printk(KERN_INFO "CBC decrypt: ");

    if(0 == strncmp((char*) out, (char*) buffer, 64))
    {
	//printk(KERN_INFO "SUCCESS!\n");
    }
    else
    {
	//printk(KERN_INFO "FAILURE!\n");
    }
}

static void test_encrypt_cbc(void)
{
    uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    uint8_t in[]  = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
	0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
	0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
	0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };
    uint8_t out[] = { 0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
	0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
	0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16, 
	0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7 };
    uint8_t buffer[64];

    AES128_CBC_encrypt_buffer(buffer, in, 64, key, iv);

    //printk(KERN_INFO "CBC encrypt: ");

    if(0 == strncmp((char*) out, (char*) buffer, 64))
    {
	//printk(KERN_INFO "SUCCESS!\n");
    }
    else
    {
	//printk(KERN_INFO "FAILURE!\n");
    }
}


static void test_decrypt_ecb(void)
{
    uint8_t key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t in[]  = {0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97};
    uint8_t out[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
    uint8_t buffer[16];

    AES128_ECB_decrypt(in, key, buffer);

    //printk(KERN_INFO "ECB decrypt: ");

    if(0 == strncmp((char*) out, (char*) buffer, 16))
    {
	//printk(KERN_INFO "SUCCESS!\n");
    }
    else
    {
	//printk(KERN_INFO "FAILURE!\n");
    }
}
/*end*/


/*
 * Pre_Routing: for inbound traffic
 *  1. Strip capability feedback from ACK packets
 */
unsigned int hook_func_in(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph = NULL;
    struct tcphdr *tcph = NULL;
    int tcplen;
    unsigned int res1;
    struct iTable *temp;
    char getCapability[capability_len];
    struct capability *cap;
    
    iph = ip_hdr(skb);

    if(mbox_networkip == 0) {
	mbox_networkip = ip_str_to_num(mbox_ip);
    }

    if(victim_networkip == 0){
	victim_networkip = ip_str_to_num(victim_ip);
    }


    /*
     * Handling traffic received from the victim:
     *	1. In PRE_ROUTING hook, we handle the capability related operations
     *	2. In POST_ROUTING hook, we rewrite the saddr as mbox's saddr
     */
    if(Add_Trim_Capability && iph->saddr == victim_networkip && iph->protocol == IPPROTO_TCP)
    {
	tcph = (struct tcphdr *)((__u32 *)iph+ iph->ihl);		
	tcplen = skb->len - ip_hdrlen(skb);

	if (ntohs(tcph->source) == 9877 && tcph->ack && (tcph->res1 != 0))
	{
	    spin_lock_irq(&mylock);	
	    temp = searchiTable(iph->daddr);

	    if((temp != NULL) && jiffies <= (temp->TA + detection_period) && temp->i <= Th_cap){
		res1 = tcph->res1;

		/*
		 * The number of capability feedback in the ACK packet is determined by the TCP option res1
		 */
		while(res1 >= 1){
		    
		    // Inspect capability feedback 
		    memcpy(getCapability, (skb->data + skb->len - res1*capability_len), capability_len);
		    cap = (struct capability *)getCapability;
		    printk(KERN_INFO "get capability skb->len:%u skb->data_len:%u id=%u saddr=%u timestamp=%lu code=%s <res1:%u>\n",skb->len, skb->data_len, cap->id, cap->saddr, cap->timestamp, cap->code, res1);

		    /*
		     * For experimental purpose, simulate the capability verification
		     */
		    test_decrypt_cbc();

		    //cTable Updates
		    computeSLR(ctab, cap->id, cap->saddr, cap->timestamp, cap->code);								  
		    /*
		     * iTable updates: 
		     *	    For simplicity, we simply increase the received capability in the iTable entry
		     *	    To avoid reply attacks, WR needs to be used as proposed in the paper
		     */
                    res1--;
		    (temp->i)++;
		}

		// Trim the capability feedback to reveal the original payload
		skb_trim(skb, skb->len - tcph->res1 * capability_len);

		// Recompute checksum to ensure correctiveness
		iph->tot_len = iph->tot_len - htons(tcph->res1 * capability_len);
		tcplen = skb->len - ip_hdrlen(skb);
		tcph->check = 0; 
		tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr, csum_partial(tcph, tcplen, 0));
		skb->ip_summed = CHECKSUM_NONE;
		ip_send_check(iph);

	    }
	    spin_unlock_irq(&mylock);

	}
    }

    /*
     * Handling traffic from the source: 
     *	1. Simply change the daddr to redirect the packet 
     *	2. The capability related handling is loaded to the POST_ROUTING hook
     */
    else if (redirect_enabled && iph->daddr == mbox_networkip && iph->protocol == IPPROTO_TCP) {
	tcph = (struct tcphdr *)((__u32 *)iph+ iph->ihl);
	tcplen = skb->len - ip_hdrlen(skb);
	if(ntohs(tcph->dest) == 9877){
        spin_lock_irq(&mylock);
	// redirect the traffic to the victim
	iph->daddr = victim_networkip; 

	// recompute the checksum
	tcph->check = 0; 
	tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr, csum_partial(tcph, tcplen, 0));
	skb->ip_summed = CHECKSUM_NONE;
	ip_send_check(iph);
        spin_unlock_irq(&mylock);
    	}
    }

    return NF_ACCEPT;                                                              
}


/*
 * Destination selectable policy one: naturalShare
 */
unsigned int naturalShare(struct iTable *s, unsigned int net_loss) {
    if (s == NULL) return 0;
    if (s->NR >= net_loss) return (s->NR - net_loss);
    else return 0;
}

/*
 * Destination selectable policy two: perSenderFairShare
 */

unsigned int perSenderFairShare(void) {
    unsigned int total_delivery = 0;
    unsigned int iTable_length = 0;
    struct iTable * t = iTable_header;
    if (iTable_header == NULL) return 0;

    while(t != NULL){
	total_delivery += t->WR;
	iTable_length += 1;
	t = t->next;
    }

    return total_delivery / iTable_length;
}


/*
 * POST_Routing: for outbound traffic
 *  1. Make policing decisions
 *  2. Encapsulate the packets in UDP destinated to the victim
 *  3. Redirect the packets from the vicimt to the client
 */
unsigned int hook_func_out(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{

    struct iphdr *iph = NULL;
    struct tcphdr *tcph = NULL;
    struct udphdr *udph = NULL;
    int original_ip_len;
    unsigned int source_ip;
    unsigned int dest_ip;
    unsigned int tot_payload_len;
    unsigned int tcplen;

    // For computing capabilities
    unsigned char *secure;
    char encryption_code[36] = "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE";
    char room[capability_len];
    struct capability *cap = room;  
    struct iTable *temp = NULL;
    unsigned int count;	

    // for loss rate
    unsigned int net_loss = 0;
    unsigned int loss_rate = 0;

    iph = ip_hdr(skb);

    if(mbox_networkip == 0) {
	mbox_networkip = ip_str_to_num(mbox_ip);
    }

    if(victim_networkip == 0){
	victim_networkip = ip_str_to_num(victim_ip);
    }


    /* 
     * Handling all packets targetting the victim (from sources)
     */ 
    if (Add_Trim_Capability && iph->daddr == victim_networkip) {
	/* 
	 * Interpret the packet 
	 */
	if (iph->protocol == IPPROTO_TCP) {
	    tcph = (struct tcphdr *)((__u32 *)iph+ iph->ihl);
	    tcplen = skb->len - ip_hdrlen(skb);

	    // irrelevent packets
	    if (ntohs(tcph->dest) != 9877 || tcph->fin) return NF_ACCEPT;


	    // Handle inner TCP packets
	    spin_lock_irq(&mylock);

	    if(load_cTable == 0){
		initialcTable(ctab);
		load_cTable = 1;
	    }

	    temp = searchiTable(iph->saddr);

	    if (temp == NULL){
		if ((temp = kmalloc(sizeof(struct iTable), GFP_KERNEL)) != NULL){
		    printk(KERN_INFO "kmalloc and create one new iTable for one new client\n");
		    temp->f = iph->saddr;
		    temp->TA = jiffies;
		    temp->PID = 0;
		    temp->NR = 0;
		    temp->ND = 0;
		    temp->WR = 0;				
		    memset(temp->WV, 0, 128);
		    temp->LR = 0;				
		    temp->next = NULL;
		}else{
		    printk(KERN_INFO "create new iTable fail\n");		
		    return NF_ACCEPT;
		}

		if (iTable_header == NULL){
		    iTable_header = temp;
		    iTable_tail = temp;

		}else{

		    iTable_tail->next = temp;
		    iTable_tail = temp;
		}

	    }

	    // reset the flow entry if the flow entry is outdated
	    if ((jiffies - temp->TA) > 10 * detection_period) {
		printk (KERN_INFO "RETSET for the sender\n");

		temp->TA = jiffies;
		temp->PID = 0;
		temp->NR = 0;
		temp->ND = 0;
		temp->WR = 0;				
		memset(temp->WV, 0, 128);
		temp->i = 0;
		temp->LR = 0;				
	    }

	    // Count the corrent packet
	    (temp->NR)++;

	    /*
	     * Best effort handling
	     */
	    if (temp->NR > temp->WR) {
		if ((temp->LR > LLR_thres) || (SLR_loss_rate > SLR_thres)) {
		    printk(KERN_INFO "Best effort rate limiting\n");
		    printk(KERN_INFO "SLR loss rate %u\n", SLR_loss_rate);
		    temp->ND += 1;
		    return NF_DROP;
		}
	    }
    
	    /*
	     * New detection period: Compute iTable entries
	     */
	    if ((jiffies - temp->TA) > detection_period) { 
		printk (KERN_INFO "New period for sender %u\n", temp->f);
		printk(KERN_INFO "PID %u\n", temp->PID);
		printk(KERN_INFO "received capability %u\n", temp->i);
		printk(KERN_INFO "early drop %u\n", temp->ND);
		printk(KERN_INFO "receive window %u\n", temp->NR);
		printk(KERN_INFO "allowed window %u\n", temp->WR);
		printk(KERN_INFO "loss rate %u\n", temp->LR);
	     
		// update iTable items
		/*
		 * For experimental purpose, the prototype simply computes the net_loss as the 
		 * number of lost capabilities
		 */
		if (temp->PID >= temp->i) {
		    net_loss = temp->ND + (temp->PID - temp->i);
		}
		else net_loss = 0;
		printk(KERN_INFO "net_loss %u\n", net_loss);

		if (temp->NR < 5) {
		    loss_rate = beta * temp->LR / 100;
		} else if (temp->NR > 0){
		    loss_rate = net_loss * 100 / temp->NR;
		    temp->LR = ((100-beta) * loss_rate + beta * temp->LR) / 100;
		}
		printk(KERN_INFO "updated LLR %u\n", temp->LR);

		/*
		 * Rate allocation: NaturalShare & PerSenderFairShare
		 */
		temp->WR = naturalShare(temp, net_loss);
		//temp->WR = perSenderFairShare(); // perSenderFairShare
		printk(KERN_INFO "updated allowed window %u\n", temp->WR);

		/*
		 * Reset for the next period
		 */
		temp->TA = jiffies;
		temp->PID = 0;
		temp->NR = 0;
		temp->ND = 0;
		memset(temp->WV, 0, 128);
		temp->i = 0;
	    } 
	
	    // Capability Handling
	    if(jiffies <= (temp->TA + detection_period - Th_rtt) && temp->PID < Th_cap){
		//If data_len is not 0, need sk_buff linerize.  zero is returned and the old skb data released.	
		skb_linearize(skb); 		
		printk(KERN_INFO "INSERT====>Before:Insert %u capability len:%0x data_len:%u tailroom:%u head:%0x data:%0x tail:%0x end:%0x iplen:%x\n", temp->PID, skb->len, skb->data_len, skb->end-skb->tail, skb->head,skb->data, skb->tail, skb->end, ntohs(iph->tot_len));
		
		if((skb->end - skb->tail) < capability_len) {
		    spin_unlock_irq(&mylock);	    
		    return NF_ACCEPT;
		}
		
		(temp->PID)++;

		
		//For simplicity of debugging, we simulate the capabilty computation by calling the CBC function
		cap->id = temp->PID;
		cap->saddr = iph->saddr;
		cap->timestamp = jiffies;
		test_encrypt_cbc();

		memcpy(cap->code, encryption_code, 36);

		// Append capability at the footer of the skb
		secure = skb_put(skb, capability_len);
		memcpy(secure, (char *)cap, capability_len);
		tcph->res1 = 0xf;

		// cTable Handling
		count = insertcTable(ctab, cap->saddr, cap->id, cap->timestamp, cap->code);
		if(count == 1) beginToTime(ctab);


		// Recompute checksum to ensure correctiveness
		iph->tot_len = iph->tot_len + htons(capability_len);
		tcplen = skb->len - ip_hdrlen(skb);

		tcph->check = 0; 
		tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr, csum_partial(tcph, tcplen, 0));
		skb->ip_summed = CHECKSUM_NONE;
		ip_send_check(iph);

	    }

	    /*
	     * UDP encapsulation
	     */

	    if (IP_in_UDP_ENCAP) {

		// remember old packet information
		source_ip = iph->saddr;
		dest_ip = iph->daddr;
		original_ip_len = ntohs(iph->tot_len);
		tot_payload_len = ntohs(iph->tot_len) - iph->ihl*4 - tcph->doff*4;

		//printk(KERN_INFO "Packet length at POST_ROUTING: %u\n", ntohs(iph->tot_len));

		/*
		 * insert new header for authenticator 
		 * 1. Insert UDP header first 
		 * 2. Then insert IP header 
		 */
		// headroom check
		if ((skb_headroom(skb) < (sizeof(struct iphdr) + sizeof(struct udphdr)))) {
		    printk(KERN_INFO "headroom is not enough for iphdr and udphdr");
		    if (pskb_expand_head(skb, (sizeof(struct iphdr) + sizeof(struct udphdr)), 0, GFP_ATOMIC) != 0) { 
			printk(KERN_INFO "headeroom is not enough");
			return NF_DROP;
		    } 
		} 
		
		/*
		if ((skb_headroom(skb) < (sizeof(struct iphdr) + sizeof(struct udphdr)))) {
		    printk(KERN_INFO "headeroom is not enough");
		    return NF_DROP;
		}
		*/

		/*UDP header*/
		udph = (struct udphdr*) skb_push(skb, sizeof(struct udphdr));
		udph->source = htons(30000);
		udph->dest = htons(30000);
		udph->len = htons(tot_payload_len); // for payload size
		udph->check = 0; // UDP checksum calculation: VXLAN's UDP checksum is 0

		/*IP header*/
		iph = (struct iphdr*) skb_push(skb, sizeof(struct iphdr));
		iph->protocol = IPPROTO_UDP;
		iph->ihl = 5;
		iph->version = 4;
		iph->tos = 0;
		iph->tot_len = htons(sizeof(struct iphdr) + original_ip_len + sizeof(struct udphdr));
		iph->id = 0;
		iph->frag_off = 0;
		iph->ttl = 60;

		// addresses
		iph->saddr = source_ip;
		iph->daddr = dest_ip;

		// compute the checksum
		skb->ip_summed = CHECKSUM_NONE;
		ip_send_check(iph);
	    }

	    spin_unlock_irq(&mylock);		
	}

    }

    /* 
     * Redirect all packets targetting the sources (from victim)
     *	1. Change the saddr as if the packet is from the mbox (which is what the source expects)
     */ 
    else if (redirect_enabled && iph->saddr == victim_networkip && iph->protocol == IPPROTO_TCP) {
	tcph = (struct tcphdr *)((__u32 *)iph + iph->ihl);
	
	if (ntohs(tcph->source) == 9877 && tcph->ack) {
	    spin_lock_irq(&mylock);
	    iph->saddr = mbox_networkip;

	    // recompute checksum
	    tcplen = skb->len - ip_hdrlen(skb);
	    tcph->check = 0; 
	    tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr, csum_partial(tcph, tcplen, 0));
	    skb->ip_summed = CHECKSUM_NONE;
	    ip_send_check(iph);
	    spin_unlock_irq(&mylock);
	}

    }

    //	printk(KERN_INFO "%lu\n", jiffies);
    return NF_ACCEPT;                                                              
}





/*Called when module loaded using insmod*/
int init_module()
{

    unsigned int i = 0;
    unsigned int f = 1;

    while(i < exist_iTable_num){
	insertiTable(f);
	f++;
	i++;
    }

    spin_lock_init(&mylock);
    nf_hook_in.hook = hook_func_in;
    nf_hook_in.hooknum = NF_INET_PRE_ROUTING;   
    nf_hook_in.pf = PF_INET;                           
    nf_hook_in.priority = NF_IP_PRI_FIRST;             
    nf_register_hook(&nf_hook_in);                     

    nf_hook_out.hook = hook_func_out; 
    nf_hook_out.hooknum = NF_INET_POST_ROUTING;   
    nf_hook_out.pf = PF_INET;                           
    nf_hook_out.priority = NF_IP_PRI_FIRST;             
    nf_register_hook(&nf_hook_out);  

    return 0;                                    
}


/*Called when module unloaded using rmmod*/
void cleanup_module()
{
    nf_unregister_hook(&nf_hook_out);      
    nf_unregister_hook(&nf_hook_in);      
}



MODULE_LICENSE("GPL");
MODULE_AUTHOR("MiddlePolice Team");
MODULE_VERSION("1.0");
MODULE_DESCRIPTION("middlepolice");
