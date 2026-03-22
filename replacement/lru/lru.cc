#include <algorithm>
#include <iterator>
#include <iomanip>

#include "cache.h"
#include "util.h"

#define L2C_SETS 1024
#define L2C_WAYS 8

#define grep_addr1 0x1
#define grep_addr2 0x1
#define grep_addr3 0x1
#define grep_addr4 0x1

#define DEBUG false

uint64_t L2_cache [L2C_SETS][L2C_WAYS];
bool L2C_prefetched [L2C_SETS][L2C_WAYS];
//uint32_t L2_freq [1024][8];
uint64_t victimL2[L2C_SETS];
uint32_t L2_secAccess[L2C_SETS];
uint16_t L2_freq [L2C_SETS][L2C_WAYS];
uint64_t L1D_cache [64][12];
uint64_t victimL1D;
//uint32_t L1D_secAccess[64];
uint64_t L1I_cache [64][8];
uint64_t victimL1I;
//uint32_t L1_freq [64][12];
uint64_t instr_num;

void CACHE::initialize_replacement() {}

uint64_t CACHE::get_instr_id() {
	return instr_num;
}

/*
uint64_t CACHE::get_victim_L2C(uint32_t LLC_set) {
	uint32_t L2_set;
	if(LLC_set>1024){
		L2_set = LLC_set-1024;
	}
	else{
		L2_set = LLC_set;
	}
	return victimL2[L2_set];
}
*/

bool CACHE::get_L2_Freq (uint32_t LLC_set, uint64_t LLC_signature) {
	uint16_t L2_set, L2_way;
	if(LLC_set>1024){
		L2_set = LLC_set-1024;
	}
	else{
		L2_set = LLC_set;
	}
	
	for(int i=0; i<L2C_WAYS; i++){
		if(LLC_signature == L2_cache[L2_set][i]){
			L2_way =i;
			if(L2_freq[L2_set][L2_way]>0){
				return true;
			}
			else
				return false;
			}
	}
	return false;
}

// find replacement victim
uint32_t CACHE::find_victim(uint32_t cpu, uint64_t instr_id, uint32_t set, const BLOCK* current_set, uint64_t ip, uint64_t full_addr, uint32_t type)
{	//const g= BLOCK* current_set;
	//cout<<"set="<<set<<" current_set="<<current_set<<" BLOCK="<<g<<endl;
	instr_num = instr_id;	
  // baseline LRU
  return std::distance(current_set, std::max_element(current_set, std::next(current_set, NUM_WAY), lru_comparator<BLOCK, BLOCK>()));
}

// called on every cache hit and cache fill
void CACHE::update_replacement_state(uint32_t cpu, uint32_t set, uint32_t way, uint64_t full_addr, uint64_t ip, uint64_t victim_addr, uint32_t type,
                                     uint8_t hit)
{
	uint64_t signature = full_addr>>6;
	//cout<<"NUM_SET="<<NUM_SET<<endl;
	
	
	if(NUM_SET==1024){				//L2C
		L2_secAccess[set]++;
		
		if(hit){
			if(type != WRITEBACK && type!= PREFETCH && L2_freq[set][way]<3){
				L2_freq[set][way]++;
				if(L2C_prefetched[set][way]) getL2C_useful_PF(L2_cache[set][way]);
			}
			victimL2[set] = 0;
			if(type==PREFETCH){
				L2C_prefetched[set][way]=true;			
			}
		}
		else{
			victimL2[set]= L2_cache[set][way];
			get_victim_L2C(victimL2[set]);
			L2_cache[set][way]= signature;
			L2_freq[set][way] = 0;
			if(type==PREFETCH){
				L2C_prefetched[set][way]=true;			
			}
			else{
				L2C_prefetched[set][way]=false;
			}
		}
		
	}
	else if(NUM_SET==64 && NUM_WAY==12){
		//L1D_secAccess[set]++;
		if(hit){
			victimL1D = 0;
		}
		else{
			victimL1D= L1D_cache[set][way];
			L1D_cache[set][way]= signature;
		}
	}
	else if(NUM_SET==64 && NUM_WAY==8){
		
		if(hit){
			victimL1I = 0;
		}
		else{
		//if(L1I_cache[set][way]!=(full_addr>>6)){
			victimL1I= L1I_cache[set][way];
			L1I_cache[set][way]= signature;
			frm_InstructionCache(L1I_cache[set][way]);
		}
	}


	if(DEBUG && (((signature == grep_addr1) || (victimL1D== grep_addr1) || (victimL2[set]== grep_addr1) ) || ((signature== grep_addr2)||( victimL1D== grep_addr2)|| (victimL2[set]== grep_addr2)) || ((signature== grep_addr3)||( victimL1D== grep_addr3)|| (victimL2[set]== grep_addr3)) || ((signature== grep_addr4)||( victimL1D== grep_addr4)|| (victimL2[set]== grep_addr4)))){
		string TYPE_NAME, cpu_type;
		if(NUM_SET==64 && NUM_WAY==12)		
			cpu_type= "L1D";
		else if(NUM_SET==64 && NUM_WAY==8)		
			cpu_type= "L1I";
		else if(NUM_SET==1024)
			cpu_type= "L2C";
		else if(NUM_SET==16)
			cpu_type= "ITLB/DTLB";
		else if(NUM_SET==128)
			cpu_type= "STLB";
		else{
			cpu_type= "unknown";
		}

		
		//if(set>449 && set< 453){
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
		else{
			assert(0);
		}

		

		if (hit){
			TYPE_NAME += "_HIT";
		}
		else{
			TYPE_NAME += "_MISS";
		}



		if ((type == WRITEBACK) && ip)
			assert(0);

		// uncomment this line to see the LLC accesses
		 cout <<cpu_type<<" CPU:" << cpu <<"  "<<setw(10)<< TYPE_NAME <<"  "<<setw(9)<<"set:"<<setw(4) << set <<"   way:"<<setw(3)<< way<<"   instr_num="<<dec<<instr_num;
		 cout << hex << "   Paddr="<<(full_addr>>6)<<"  ip:"<<setw(10) << ip <<"  victim_addr="<< victim_addr<<dec;

		if(cpu_type=="L2C"){
			cout<<"  L2_victim_addr="<<hex<<victimL2[set]<< dec <<" setAccess="<<L2_secAccess[set]<< endl;
		}
		else if(cpu_type=="L1D"){
			cout<<"  L1D_victim_addr="<<hex<<victimL1D<< dec<<endl;
		}
		else if(cpu_type=="L1I"){
			cout<<"  L1I_victim_addr="<<hex<<victimL1I<< dec << endl;
		}
		else
			cout<<endl;
	}
	
	
	
	/*
	if(NUM_SET==64 && NUM_WAY==8) {
		string TYPE_NAME, cpu_type;
		cpu_type= "L1I";

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
		else{
			assert(0);
		}

		if (hit){
			TYPE_NAME += "_HIT";
		}
		else{
			TYPE_NAME += "_MISS";
		}

		cout <<cpu_type<<" CPU:" << cpu <<"  "<<setw(10)<< TYPE_NAME <<"  "<<setw(9)<<"set:"<<setw(4) << set <<"   way:"<<setw(3)<< way<<"   instr_num="<<instr_num;
		cout << hex << "   Paddr="<<(full_addr>>6)<<"  ip:"<<setw(10) << ip <<"  victim_addr:"<<setw(2) << victim_addr;
		
		if(cpu_type=="L2C"){
			cout<<"  L2_victim:"<<setw(12)<<victimL2[set]<< dec <<" setAccess="<<L2_secAccess[set]<< endl;
		}
		else if(cpu_type=="L1D"){
			cout<<"  L1D_victim:"<<setw(12)<<victimL1D<< dec<<endl;
		}
		else if(cpu_type=="L1I"){
			cout<<"  L1I_victim:"<<setw(12)<<victimL1I<< dec << endl;
		}
		else
			cout<<endl;
	}
	*/
	
	
  if (hit && type == WRITEBACK)
    return;

  auto begin = std::next(block.begin(), set * NUM_WAY);
  auto end = std::next(begin, NUM_WAY);
  uint32_t hit_lru = std::next(begin, way)->lru;
  std::for_each(begin, end, [hit_lru](BLOCK& x) {
    if (x.lru <= hit_lru)
      x.lru++;
  });
  std::next(begin, way)->lru = 0; // promote to the MRU position
}

void CACHE::replacement_final_stats() {}
