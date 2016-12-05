#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <net/tcp.h>
#include <net/ip.h>
#include <linux/spinlock.h>

#define exist_capabilitylist_num 0
#define capability_len 60

char mbox_ip[15] = "192.168.1.174";
char victim_ip[15] = "192.168.2.253";
unsigned int mbox_networkip = 0;
unsigned int victim_networkip = 0;

static spinlock_t mylock;

static struct nf_hook_ops nf_hook_in;
static struct nf_hook_ops nf_hook_out;


/*
 * The followings are core data structures for storing and processing received capabilities
 * See our architecture for details
 */
struct capability {
    unsigned int id; // capability ID
    unsigned int saddr;	// the source address of the sender	
    unsigned long timestamp; // the time when a packet arrived at the mbox
    char code[capability_len - 16]; // MAC
};


struct capability_list{
    char code[capability_len];
    struct capability_list * next;
};

struct capability_header{
    unsigned int saddr;
    struct capability_list *first;  
    struct capability_list *end;
    struct capability_header *next;
};


struct capability_header * header = NULL;
struct capability_header * tail = NULL;



struct capability_header *searchCapabilityHeader(unsigned int addr){
    struct capability_header *q = header;
    while(q != NULL && q->saddr != addr){
	q = q->next;

    }

    return q;

}


unsigned int insertCapabilityList(unsigned int srcaddr){

    struct capability_header *h = NULL;

    if ((h = kmalloc(sizeof(struct capability_header), GFP_KERNEL)) != NULL){
	printk(KERN_INFO "insertCapabilityList===>malloc and create capability header:%u\n", srcaddr);
	h->saddr = srcaddr;
	h->first = NULL;
	h->end = NULL;
	h->next = NULL;

    }else{
	printk(KERN_INFO "malloc capabilitylist failed.\n");
	return 0;
    }

    if(header == NULL){
	header = h;
	tail = h;

    }else{

	tail->next = h;
	tail = h;

    }
    return 1;

}

unsigned int ip_str_to_num(const char *buf)
{

    unsigned int tmpip[4] = {0};
    unsigned int tmpip32 = 0;
    sscanf(buf, "%d.%d.%d.%d", &tmpip[0], &tmpip[1], &tmpip[2], &tmpip[3]);
    tmpip32 = (tmpip[3]<<24) | (tmpip[2]<<16) | (tmpip[1]<<8) | tmpip[0];
    return tmpip32;
}





/*
 * Pre_Routing: For inbound traffic
 */
unsigned int hook_func_in(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{

    struct iphdr *iph = NULL;
    struct tcphdr *tcph = NULL;
    /*
    struct udphdr *udph = NULL;
    int original_ip_len;
    unsigned int source_ip;
    unsigned int dest_ip;
    unsigned int tot_payload_len;
    */
    unsigned int tcplen;

    struct capability_list *p = NULL;
    struct capability_header *h = NULL;

    struct capability *cap = NULL;

    // irrelevent packets
    //if (!in) return NF_ACCEPT;

    iph = ip_hdr(skb);

    if(mbox_networkip == 0) {
	mbox_networkip = ip_str_to_num(mbox_ip);
    }

    if(victim_networkip == 0){
	victim_networkip = ip_str_to_num(victim_ip);
    }


    /*
     * Handling all packets targetting the victim
     */
    if(iph->daddr == victim_networkip) {
	/*
	 * Strip the outer IP/UDP header
	 * In some case, the linux kernel will strip packets for us :) 
	 */
	if (iph->protocol == IPPROTO_UDP) {

	    // remove the outer IP and UDP header
	    if (skb->len < (sizeof(struct iphdr) + sizeof(struct udphdr) + 40)) {
		printk(KERN_INFO "Packets without encapsulation !!!!");
		return NF_ACCEPT;
	    } 

	    //strip the ip and udp header
	    iph = (struct iphdr*) skb_pull(skb, (sizeof(struct iphdr) + sizeof(struct udphdr)));
	    // offset the skb_buff
	    skb->network_header += (sizeof(struct iphdr) + sizeof(struct udphdr));
	    skb->transport_header += (sizeof(struct iphdr) + sizeof(struct udphdr));

	    //printk(KERN_INFO "PRE_ROUTING: Packets have been decapsulated.\n");
	    //printk(KERN_INFO "PRE_ROUTING: Packet length after stripping: %u\n", skb->len);
	}
    

	// interpret inner TCP packets
	if(iph->protocol == IPPROTO_TCP) {

	    tcph = (struct tcphdr *)((__u32 *)iph+ iph->ihl);	
	    tcplen = skb->len - ip_hdrlen(skb);

	    // irrelevent packets
	    if (ntohs(tcph->dest) != 9877 || tcph->res1 != 0xf) return NF_ACCEPT;

	    spin_lock_irq(&mylock);


	    /*
	     * Store the capability in the right place
	     */
	    h = searchCapabilityHeader(iph->saddr);
	    if (h == NULL) {
		if ((h = kmalloc(sizeof(struct capability_header), GFP_KERNEL)) != NULL){
		    //printk(KERN_INFO "malloc and create capability header.\n");
		    h->saddr = iph->saddr;
		    h->first = NULL;
		    h->end = NULL;
		    h->next = NULL;

		}else{
		    printk(KERN_INFO "malloc capability_header fail.\n");
		}

		if(header == NULL) {
		    header = h;
		    tail = h;

		} else {
		    tail->next = h;
		    tail = h;
		}
	    }


	    if ((p = kmalloc(sizeof(struct capability_list), GFP_KERNEL)) != NULL){
		memcpy(p->code, (skb->data + skb->len - capability_len), capability_len);

		cap = (struct capability *)p->code;
		printk(KERN_INFO "skb->len:%u skb->data_len:%u tailroom:%u kmalloc and copy into cap->id:%u cap->saddr:%u cap->timestamp:%lu cap->code:%s\n", skb->len, skb->data_len, skb->end - skb->tail, cap->id, cap->saddr, cap->timestamp, cap->code);

		p->next = NULL;
	    }			

	    if (h->first == NULL)
	    {
		h->first = p;
		h->end = p;

	    } else {

		h->end->next = p;
		h->end = p;
	    }
	    spin_unlock_irq(&mylock);			

	    // Trim capability to reveal original payloads
	    skb_trim(skb, skb->len - capability_len);

	    // Recompute checksum for correctiveness
	    iph->tot_len = iph->tot_len - htons(capability_len);
	    tcplen = skb->len - ip_hdrlen(skb);
	    tcph->check = 0; 
	    tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr, csum_partial(tcph, tcplen, 0));
	    skb->ip_summed = CHECKSUM_NONE;
	    ip_send_check(iph);
	}
    }
    return NF_ACCEPT;                                                              
}


/*
 * POST_Routing: for outbound traffic
 */
unsigned int hook_func_out(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph = NULL;
    struct tcphdr *tcph = NULL;
    int tcplen;
    char * secure;
    unsigned int count = 0;


    struct capability_header *f = NULL;
    struct capability_list *temp = NULL;
    struct capability_list *temp2 = NULL;

    struct capability *cap = NULL;

    //if (!in) return NF_ACCEPT;

    iph = ip_hdr(skb);

    if(mbox_networkip == 0) {
	mbox_networkip = ip_str_to_num(mbox_ip);
    }

    if(victim_networkip == 0){
	victim_networkip = ip_str_to_num(victim_ip);
    }


    if(iph->protocol == IPPROTO_TCP)
    {
	tcph = (struct tcphdr *)((__u32 *)iph+ iph->ihl);		

	tcplen = skb->len - ip_hdrlen(skb);

	/*
	 * Carry capability feedbacks using ACK packets
	 */
	if(iph->saddr == victim_networkip && ntohs(tcph->source) == 9877 && tcph->ack)
	{			
	    //printk(KERN_INFO "ADD===>Before:len:%0x tailroom:%0x head:%0x data:%0x tail:%0x end:%0x data_len:%0x\n", skb->len,skb->end-skb->tail, skb->head,skb->data, skb->tail, skb->end, skb->data_len);

	    spin_lock_irq(&mylock);

	    /*
	     * The number of packets carried in the ACK is count
	     */
	    f = searchCapabilityHeader(iph->daddr);
	    if(f != NULL){
		while((f->first != NULL) && (skb->end - skb->tail) >= capability_len && count < 0x03){		
		    temp = f->first;
		    secure = skb_put(skb, capability_len);

		    cap = (struct capability *)temp->code;					
		    //printk(KERN_INFO "skb->len:%u skb->data_len:%u add num:%u saddr:%u timestamp:%lu code:%s in ACK <%u>\n", skb->len, skb->data_len, cap->num, cap->saddr, cap->timestamp, cap->code, count);					
		    memcpy(secure, temp->code, capability_len);
		    temp2 = temp;
		    temp = temp->next;
		    kfree(temp2);
		    f->first = temp;
		    if(f->first == NULL) f->end = NULL;
		    count++;
		}			

	    }
	    //printk(KERN_INFO "count:%u\n", count);
	    tcph->res1 = count;

	    //printk(KERN_INFO "ADD===>After:len:%0x tailroom:%0x head:%0x data:%0x tail:%0x end:%0x data_len:%0x\n", skb->len,skb->end-skb->tail, skb->head,skb->data, skb->tail, skb->end, skb->data_len);

	    // Recompute checksum for correctiveness
	    iph->tot_len = iph->tot_len + htons(capability_len * count);
	    tcplen = skb->len - ip_hdrlen(skb);
	    tcph->check = 0; 
	    tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr, csum_partial(tcph, tcplen, 0));
	    skb->ip_summed = CHECKSUM_NONE;
	    ip_send_check(iph);

	    /*
	     * For experimental purpose, IP-tunnel is not necessary due to sementric topology
	     */

	    spin_unlock_irq(&mylock);
	}


    }

    return NF_ACCEPT;                                                              
}


/*Called when module loaded using insmod*/
int init_module()
{
    unsigned int i = 0;
    unsigned int f = 1;

    while(i < exist_capabilitylist_num){
	insertCapabilityList(f);
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
    nf_unregister_hook(&nf_hook_in);   
    nf_unregister_hook(&nf_hook_out);                
}



MODULE_LICENSE("GPL");
MODULE_AUTHOR("MiddlePolice Team");
MODULE_VERSION("1.0");
MODULE_DESCRIPTION("middlepolice");

