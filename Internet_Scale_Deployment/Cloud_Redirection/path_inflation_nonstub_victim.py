#!/usr/bin/env python

# This program first reconstructs the Internet AS relationships based on the Internet routing policies; and then it computes both the direct and redirected AS_level path between an access AS and an victim AS

import commands, pdb, math, itertools, pprint, sys, random
import networkx as nx

# Represent the Internet as a directed graph, whose edge's weigth is determined by the routing
# weight: p->c: 1; c->p; 100; p->p: 2. Smaller weights are preferable
p2c_weight = 1
c2p_weight = 100
p2p_weight = 10

ASs = []
AS_relation = {}

AS_Internet = nx.DiGraph()


with open('20151201.as-rel.txt', 'r') as f:
    for line in f:
        if '|' not in line:
            continue

        attributes = str.split(line, '|')
        if not len(attributes) == 3:
            continue 

        # p2c relationship
        if '-1' in attributes[2]:
            p_AS = attributes[0]
            c_AS = attributes[1]

            # provider AS
            if p_AS not in ASs:
                ASs.append(p_AS)

            if p_AS not in AS_relation:
                AS_relation[p_AS] = {}
                AS_relation[p_AS]['customers'] = []
                AS_relation[p_AS]['providers'] = []
                AS_relation[p_AS]['peers'] = []

            if c_AS not in AS_relation[p_AS]['customers']:
                AS_relation[p_AS]['customers'].append(c_AS)

            # customer AS
            if c_AS not in ASs:
                ASs.append(c_AS)

            if c_AS not in AS_relation:
                AS_relation[c_AS] = {}
                AS_relation[c_AS]['customers'] = []
                AS_relation[c_AS]['providers'] = []
                AS_relation[c_AS]['peers'] = []

            if p_AS not in AS_relation[c_AS]['providers']:
                AS_relation[c_AS]['providers'].append(p_AS)

            # add two edges in the Internet 
            AS_Internet.add_edge(p_AS, c_AS, weight=p2c_weight)
            AS_Internet.add_edge(c_AS, p_AS, weight=c2p_weight)

            

        # p2p relationship
        if '0' in attributes[2]:
            peer_AS1 = attributes[0]
            peer_AS2 = attributes[1]

            # peer-one AS
            if peer_AS1 not in ASs:
                ASs.append(peer_AS1)

            if peer_AS1 not in AS_relation:
                AS_relation[peer_AS1] = {}
                AS_relation[peer_AS1]['customers'] = []
                AS_relation[peer_AS1]['peers'] = []
                AS_relation[peer_AS1]['providers'] = []

            if peer_AS2 not in AS_relation[peer_AS1]['peers']:
                AS_relation[peer_AS1]['peers'].append(peer_AS2)


            # peer2 AS
            if peer_AS2 not in ASs:
                ASs.append(peer_AS2)

            if peer_AS2 not in AS_relation:
                AS_relation[peer_AS2] = {}
                AS_relation[peer_AS2]['customers'] = []
                AS_relation[peer_AS2]['peers'] = []
                AS_relation[peer_AS2]['providers'] = []

            if peer_AS1 not in AS_relation[peer_AS2]['peers']:
                AS_relation[peer_AS2]['peers'].append(peer_AS1)

            # add to the Internet 
            AS_Internet.add_edge(peer_AS1, peer_AS2, weight=p2p_weight)
            AS_Internet.add_edge(peer_AS2, peer_AS1, weight=p2p_weight)



f.close()
 
stub_ASes = {'stub_ASes': []}
core_ASes = {'core_ASes': []}

for AS in ASs:
    if len(AS_relation[AS]['customers']) == 0:
        stub_ASes['stub_ASes'].append(AS)

    if len(AS_relation[AS]['providers']) == 0:
        core_ASes['core_ASes'].append(AS)

ff = open('stub_ASes.py', 'w+')
pprint.pprint(stub_ASes, ff)
ff.close()

ff = open('core_ASes.py', 'w+')
pprint.pprint(core_ASes, ff)
ff.close()

stubASes = stub_ASes['stub_ASes']
coreASes = core_ASes['core_ASes']

##############################################################
# Begin to analyze the direct and redirected path
##############################################################


# '13335' is CloudFlare, '16509' is EC2
cloud = '16509'

# You can set larger the sampled_count
sampled_victim_count = 5
sampled_access_AS_count = 5

sampled_victim_ASs = [] # non-stub victim AS
while len(sampled_victim_ASs) < sampled_victim_count:
    no_stub_victim = ASs[random.randint(0,len(ASs)-1)]
    if no_stub_victim not in stubASes:
        sampled_victim_ASs.append(no_stub_victim)

sampled_access_ASs = random.sample(ASs, sampled_access_AS_count)


# format: {vicitim_AS: {Access_AS: {'redirect': path_length, 'direct': path_length}}}
hop_status = {}

counter = 0
for victim_AS in sampled_victim_ASs:
    access_AS_direct_path_to_victim = {}
    access_AS_path_to_cloud = {}
    access_AS_redirect_path_to_victim = {}

    print "Processing %s-th victim AS with ASN %s" % (str(counter), victim_AS)
    counter += 1

    for access_AS in sampled_access_ASs:
        if access_AS == victim_AS:
            continue

        #print 'Access AS'
        #print access_AS

        # obtain the direct path to the victim AS
        paths = []
        for path in nx.all_shortest_paths(AS_Internet, source=access_AS, target=victim_AS, weight='weight'):
            is_valid = True

            # valid path condistion: every tranmit must be paid
            for i in range(len(path)):
                if i == len(path) - 1:
                    continue

                cur_AS = path[i]
                next_AS = path[i+1]

                if next_AS in AS_relation[cur_AS]['customers'] and (not next_AS == victim_AS):
                    # the next hop of next_AS must pay next_AS
                    if i+2 == len(path): # no next hop of next_AS
                        is_valid = False
                        break

                    next_next_AS = path[i+2]
                    if not next_next_AS in AS_relation[next_AS]['customers']:# no one pays next_AS
                        is_valid = False
                        break

                if not is_valid:
                    continue
                else:
                    paths.append(path)


        if len(paths) == 0:
            print 'no valid path from access_AS ' + str(access_AS) + ' to victim ' + str(victim_AS)
            continue
        
        if access_AS not in access_AS_direct_path_to_victim:
            access_AS_direct_path_to_victim[access_AS] = {}

        # random tie break 
        access_AS_direct_path_to_victim[access_AS]['path'] = paths[random.randint(0,len(paths)-1)]
        #print 'direct path'
        #print access_AS_direct_path_to_victim[access_AS]['path']


        # Obtain the rerouted path to the victim: from access AS to the cloud and then from the cloud to the victim
        # We do not study the route from victim to the acccess AS

        # the first half: from access to the cloud
        paths = []
        for path in nx.all_shortest_paths(AS_Internet, source=access_AS, target=cloud, weight='weight'):
            is_valid = True

            # valid path condistion: every tranmit must be paid
            for i in range(len(path)):
                if i == len(path) - 1:
                    continue

                cur_AS = path[i]
                next_AS = path[i+1]

                if next_AS in AS_relation[cur_AS]['customers'] and (not next_AS == victim_AS):
                    # the next hop of next_AS must pay next_AS
                    if i+2 == len(path): # no next hop of next_AS
                        is_valid = False
                        break

                    next_next_AS = path[i+2]
                    if not next_next_AS in AS_relation[next_AS]['customers']:# no one pays next_AS
                        is_valid = False
                        break

                if not is_valid:
                    continue
                else:
                    paths.append(path)


        if len(paths) == 0:
            print 'no valid path'
            continue

        if access_AS not in access_AS_path_to_cloud:
            access_AS_path_to_cloud[access_AS] = {}

        # random tie break 
        access_AS_path_to_cloud[access_AS]['path'] = paths[random.randint(0,len(paths)-1)]

        #print 'direct path'
        #print access_AS_direct_path_to_victim[access_AS]['path']


        # the second half: from cloud to the victim
        paths = []
        for path in nx.all_shortest_paths(AS_Internet, source=cloud, target=victim_AS, weight='weight'):
            is_valid = True

            # valid path condistion: every tranmit must be paid
            for i in range(len(path)):
                if i == len(path) - 1:
                    continue

                cur_AS = path[i]
                next_AS = path[i+1]

                if next_AS in AS_relation[cur_AS]['customers'] and (not next_AS == victim_AS):
                    # the next hop of next_AS must pay next_AS
                    if i+2 == len(path): # no next hop of next_AS
                        is_valid = False
                        break

                    next_next_AS = path[i+2]
                    if not next_next_AS in AS_relation[next_AS]['customers']:# no one pays next_AS
                        is_valid = False
                        break

                if not is_valid:
                    continue
                else:
                    paths.append(path)


        if len(paths) == 0:
            print 'no valid path'
            continue

        
        if access_AS not in access_AS_redirect_path_to_victim:
            access_AS_redirect_path_to_victim[access_AS] = {}

        access_AS_to_cloud = access_AS_path_to_cloud[access_AS]['path']
        cloud_to_victim = paths[random.randint(0,len(paths)-1)]

        access_AS_redirect_path_to_victim[access_AS]['path'] = [] 
        access_AS_redirect_path_to_victim[access_AS]['path'].extend(access_AS_to_cloud) 
        access_AS_redirect_path_to_victim[access_AS]['path'].extend(cloud_to_victim) 
        #print 'Redirect path'
        #print access_AS_redirect_path_to_victim[access_AS]['path']


        # determine hop inflation after routing and short_cut percentage
        if victim_AS not in hop_status:
            hop_status[victim_AS] = {}

        if access_AS not in hop_status[victim_AS]:
            hop_status[victim_AS][access_AS] = {}

        hop_status[victim_AS][access_AS]['direct'] = len(access_AS_direct_path_to_victim[access_AS]['path'])
        hop_status[victim_AS][access_AS]['reroute'] = len(access_AS_redirect_path_to_victim[access_AS]['path']) - 1


    # store the result in files for analysis
    ff = open('access_AS_redirect_path_to_nonstub_victim.py', 'a+')
    pprint.pprint(access_AS_redirect_path_to_victim, ff)
    ff.close()

    ff = open('access_AS_direct_path_to_nonstub_victim.py', 'a+')
    pprint.pprint(access_AS_direct_path_to_victim, ff)
    ff.close()

    '''
    if cloud == '13335':
        ff = open('nonstub_victim_access_AS_to_CloudFlare.py', 'a+')
    elif cloud == '16509':
        ff = open('nonstub_victim_access_AS_to_EC2.py', 'a+')
    else:
        ff = open('nonstub_victim_access_AS_to_cloud.py', 'a+')
    pprint.pprint(access_AS_to_cloud, ff)
    ff.close()
    '''



if cloud == '13335':
    ff = open('nonstub_victim_cloudflare_hop_result.py', 'a+')
elif cloud == '16509':
    ff = open('nonstub_victim_EC2_hop_result.py', 'a+')
else:
    ff = open('nonstub_victim_hop_result.py', 'a+')
pprint.pprint(hop_status, ff)
ff.close()
