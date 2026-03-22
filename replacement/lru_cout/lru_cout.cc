#include "cache.h"
#include <iomanip>
#include <map>

#define LLC_SETS 2048
#define LLC_WAYS 16
#define DEBUG false

uint32_t lru[LLC_SETS][LLC_WAYS];

uint64_t llc_addr[LLC_SETS][LLC_WAYS];
uint64_t llc_victim;
uint16_t SetAccess[LLC_SETS];
uint64_t signature;
uint32_t reuse_freq503[500], reuse_freq504[500];

struct ADDR_INFO2
{
    uint16_t distance;
	uint32_t access;
	

	void init()
    {
   		distance = 0;
		access = 0;
    }
};
map<uint64_t, ADDR_INFO2> rDistr503;
uint32_t WB_hit_503=0, WB_hit_504=0;

void CACHE::get_victim_L2C(uint64_t L2victim) {	
	return;
}

void CACHE::frm_InstructionCache(uint64_t L1Iblock){
 
	return;
}
void CACHE::getL2C_useful_PF(uint64_t useful_addr){
	return;
}

// initialize replacement state
void CACHE::initialize_replacement()
{
	for (int i=0; i<LLC_SETS; i++) {
        for (int j=0; j<LLC_WAYS; j++) {
            lru[i][j] = j;
        }
    }
	cout<<"LRU initialization"<<endl;
	cout<<"TRANSLATION value="<<TRANSLATION<<endl;
}

uint64_t instr_num2, instr_num3;

// find replacement victim
uint32_t CACHE::find_victim(uint32_t cpu, uint64_t instr_id, uint32_t set, const BLOCK *current_set, uint64_t ip, uint64_t full_addr, uint32_t type)
{	
	instr_num3= instr_id;
	//cout<<"llc instr_id ="<<instr_id<<endl;
    // baseline LRU
    for (int i=0; i<LLC_WAYS; i++)
    	if (lru[set][i] == (LLC_WAYS-1))
            return i;

    return 0;
}

// called on every cache hit and cache fill
void CACHE::update_replacement_state(uint32_t cpu, uint32_t set, uint32_t way, uint64_t full_addr, uint64_t ip, uint64_t victim_addr, uint32_t type, uint8_t hit)
{	
	SetAccess[set]++;
	signature= full_addr>>6;
	
	
	if( rDistr503.find(signature) != rDistr503.end()){
		if(type != WRITEBACK){
			rDistr503[signature].distance = SetAccess[set]-rDistr503[signature].access;
			//cout<<"line 448 rDistr503["<<signature<<"].distance:"<<rDistr503[signature].distance<<endl;
			rDistr503[signature].access= SetAccess[set];

			if(rDistr503[signature].distance<500){
				reuse_freq503[rDistr503[signature].distance]++;
				
				if(hit)
					reuse_freq504[rDistr503[signature].distance]++;
				//cout<<"line 452 reuse_freq475["<<rDistr503[signature].distance<<"]:"<<reuse_freq503[rDistr503[signature].distance]<<endl;
			}
		}
		else{
			WB_hit_503++;
			if(hit)
				WB_hit_504++;
		}		
	}
	else{
		rDistr503[signature].access= SetAccess[set];
		//cout<<"line 462 rDistr503["<<signature<<"].access"<<rDistr503[signature].access<<endl;
	}

	if(llc_addr[set][way] != signature){
		llc_victim = llc_addr[set][way];
		llc_addr[set][way]= signature;
	}

	
	//cout<<"#instr_id from victim func="<<instr_num3<<endl;
	instr_num2= get_instr_id();
	//cout<<" getting instr id="<<instr_num2<<endl;


if(DEBUG && (set>=1471 && set<1601)){	
    string TYPE_NAME;
    if (type == LOAD)
        TYPE_NAME = "LOAD";
    else if (type == RFO)
        TYPE_NAME = "RFO";
    else if (type == PREFETCH)
        TYPE_NAME = "PF";
    else if (type == WRITEBACK)
        TYPE_NAME = "WB";
    else if (type == TRANSLATION)
		TYPE_NAME = "TL";
	else
        assert(0);

    if (hit)
        TYPE_NAME += "_HIT";
    else
        TYPE_NAME += "_MISS";

    if ((type == WRITEBACK) && ip)
        assert(0);

    // uncomment this line to see the LLC accesses
     cout << "CPU:" << cpu <<"	  "<< TYPE_NAME <<"    LLC   set:" << set <<"    way:" << way<<" 	instr_num="<<instr_num2;
     cout << hex << "   Paddr="<< signature <<"   ip:" << ip <<" llc_victim_addr="<<llc_victim<< dec <<"  SetAccess:"<<SetAccess[set]<< endl;
}



	llc_victim = 0; 
	//cout<<" NUM_WAY="<<NUM_WAY<<endl;

    // baseline LRU
   for (uint32_t i=0; i<LLC_WAYS; i++) {
        if (lru[set][i] < lru[set][way]) {
            lru[set][i]++;

            if (lru[set][i] == LLC_WAYS)
                assert(0);
        }
    }
    lru[set][way] = 0;
}


void CACHE::replacement_final_stats()
{

	uint32_t total_hit_504=0;
	cout<<"total hit distribution in LRU *******************"<<endl;
	for(int i=0; i<500; i++){	
		cout<<"reuse_freq_distance["<<i<<"]:"<<reuse_freq504[i];
		total_hit_504= total_hit_504+reuse_freq504[i];
		cout<<" total:"<<total_hit_504<<endl;
	}
	cout<<"total_hit without WB**="<<total_hit_504<<endl;
	cout<<"writeback hit in TCRH:"<<WB_hit_504<<endl;
	total_hit_504 = total_hit_504+WB_hit_504;
	cout<<"Total_hit_***="<<total_hit_504<<endl;
}

