////////////////////////////////////////////
//                                        //
//     SRRIP [Jaleel et al. ISCA' 10]     //
//     Jinchun Kim, cienlux@tamu.edu      //
//                                        //
////////////////////////////////////////////
//
#include "cache.h"
#include <iomanip>


#define NUM_CORE 4
#define MAX_LLC_SETS NUM_CORE*2048
#define LLC_WAYS 16

#define SAT_INC(x,max)  (x<max)?x+1:x
#define SAT_DEC(x)      (x>0)?x-1:x
#define TRUE 1
#define FALSE 0

#define RRIP_OVERRIDE_PERC   0
#define DEBUG false

void CACHE::get_victim_L2C(uint64_t L2victim) {	
	return;
}

// The base policy is SRRIP. SHIP needs the following on a per-line basis
#define maxRRPV 3
uint32_t line_rrpv[MAX_LLC_SETS][LLC_WAYS];
uint32_t is_prefetch[MAX_LLC_SETS][LLC_WAYS];
uint32_t fill_core[MAX_LLC_SETS][LLC_WAYS];

// These two are only for sampled sets (we use 64 sets)
#define NUM_LEADER_SETS   64

uint32_t ship_sample[MAX_LLC_SETS];
uint32_t line_reuse[MAX_LLC_SETS][LLC_WAYS];
uint64_t line_sig[MAX_LLC_SETS][LLC_WAYS];
	
// SHCT. Signature History Counter Table
// per-core 16K entry. 14-bit signature = 16k entry. 3-bit per entry
#define maxSHCTR 7
#define SHCT_SIZE (1<<14)
uint32_t SHCT[NUM_CORE][SHCT_SIZE];

// Statistics
uint64_t insertion_distrib[NUM_TYPES][maxRRPV+1];
uint64_t total_prefetch_downgrades;
uint64_t instr_num2;
uint32_t LLC_secAccess[MAX_LLC_SETS];
uint64_t LLC_cache [MAX_LLC_SETS][LLC_WAYS];

void CACHE::frm_InstructionCache(uint64_t L1Iblock){
	return;
}
// initialize replacement state

void CACHE::initialize_replacement()
{
    int LLC_SETS = MAX_LLC_SETS;

    cout << "Initialize SRRIP state" << endl;
	cout<<" NUM_LEADER_SETS:"<<NUM_LEADER_SETS<<endl;

    for (int i=0; i<MAX_LLC_SETS; i++) {
        for (int j=0; j<LLC_WAYS; j++) {
            line_rrpv[i][j] = maxRRPV;
            line_reuse[i][j] = FALSE;
            is_prefetch[i][j] = FALSE;
            line_sig[i][j] = 0;
        }
    }

    for (int i=0; i<NUM_CORE; i++) {
        for (int j=0; j<SHCT_SIZE; j++) {
            SHCT[i][j] = 1; // Assume weakly re-use start
        }
    }

    int leaders=0;
	
    while(leaders<NUM_LEADER_SETS){
      int randval = rand()%LLC_SETS;
	  
      if(ship_sample[randval]==0){
		ship_sample[randval]=1;
		leaders++;
      }
    }
}

// find replacement victim
// return value should be 0 ~ 15 or 16 (bypass)
uint32_t CACHE::find_victim(uint32_t cpu, uint64_t instr_id, uint32_t set, const BLOCK *current_set, uint64_t ip, uint64_t full_addr, uint32_t type)
{
	instr_num2 = instr_id;
    // look for the maxRRPV line
    while (1)
    {
        for (int i=0; i<LLC_WAYS; i++)
            if (line_rrpv[set][i] == maxRRPV) { // found victim
                return i;
            }

        for (int i=0; i<LLC_WAYS; i++)
            line_rrpv[set][i]++;
    }

    // WE SHOULD NOT REACH HERE
    assert(0);
    return 0;
}

// called on every cache hit and cache fill
void CACHE::update_replacement_state(uint32_t cpu, uint32_t set, uint32_t way, uint64_t full_addr, uint64_t ip, uint64_t victim_addr, uint32_t type, uint8_t hit)
{
  uint32_t sig   = line_sig[set][way];
  LLC_secAccess[set]++;

    if (hit) { // update to REREF on hit
        if( type != WRITEBACK ) 
        {

            if( (type == PREFETCH) && is_prefetch[set][way] )
            {
//                line_rrpv[set][way] = 0;
                
                if( (ship_sample[set] == 1) && ((rand()%100 <5) || (cpu==4))) 
                {
                    uint32_t fill_cpu = fill_core[set][way];

                    SHCT[fill_cpu][sig] = SAT_INC(SHCT[fill_cpu][sig], maxSHCTR);
                    line_reuse[set][way] = TRUE;
                }
            }
            else 
            {
                line_rrpv[set][way] = 0;

                if( is_prefetch[set][way] )
                {
                    line_rrpv[set][way] = maxRRPV;
                    is_prefetch[set][way] = FALSE;
                    total_prefetch_downgrades++;
                }

                if( (ship_sample[set] == 1) && (line_reuse[set][way]==0) ) 
                {
                    uint32_t fill_cpu = fill_core[set][way];

                    SHCT[fill_cpu][sig] = SAT_INC(SHCT[fill_cpu][sig], maxSHCTR);
                    line_reuse[set][way] = TRUE;
                }
            }
        }
    
	if(DEBUG){
		if(set>1471 && set<1601){
			string TYPE_NAME, cpu_type;
			cpu_type= "LLC";

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

			cout <<cpu_type<<" CPU:" << cpu <<"  "<< TYPE_NAME <<"  "<<setw(9)<<"set:"<<setw(4) <<dec<< set <<"   way:"<<setw(3)<< way<<" instr_num="<<instr_num2<<" secAccess:"<<LLC_secAccess[set];
			cout << hex << "   Paddr="<<(full_addr>>6)<<"  ip:"<<setw(10) << ip <<"  victim_addr:"<<setw(2) << victim_addr<<" rrpv:"<<dec<<line_rrpv[set][way]<<" SHCT:"<<SHCT[cpu][sig]<<endl;   
		}
	}
	return;
    }
    
    //--- All of the below is done only on misses -------
    // remember signature of what is being inserted
    uint64_t use_PC = (type == PREFETCH ) ? ((ip << 1) + 1) : (ip<<1);
    uint32_t new_sig = use_PC%SHCT_SIZE;
	victim_addr = LLC_cache[set][way];
	LLC_cache[set][way] = full_addr>>6;
	
    
    if( ship_sample[set] == 1 ) 
    {
        uint32_t fill_cpu = fill_core[set][way];
        
        // update signature based on what is getting evicted
        if (line_reuse[set][way] == FALSE) { 
            SHCT[fill_cpu][sig] = SAT_DEC(SHCT[fill_cpu][sig]);
        }
        else 
        {
            SHCT[fill_cpu][sig] = SAT_INC(SHCT[fill_cpu][sig], maxSHCTR);
        }

        line_reuse[set][way] = FALSE;
        line_sig[set][way]   = new_sig;  
        fill_core[set][way]  = cpu;
    }



    is_prefetch[set][way] = (type == PREFETCH);

    // Now determine the insertion prediciton

    uint32_t priority_RRPV = maxRRPV-1 ; // default SHIP

    if( type == WRITEBACK )
    {
        line_rrpv[set][way] = maxRRPV;
    }
    else if (SHCT[cpu][new_sig] == 0) {
      line_rrpv[set][way] = (rand()%100>=RRIP_OVERRIDE_PERC)?  maxRRPV: priority_RRPV; //LowPriorityInstallMostly
    }
    else if (SHCT[cpu][new_sig] == 7) {
        line_rrpv[set][way] = (type == PREFETCH) ? 1 : 0; // HighPriority Install
    }
    else {
        line_rrpv[set][way] = priority_RRPV; // HighPriority Install 
    }
	
	if(DEBUG){
		if(set>1471 && set<1601){
			string TYPE_NAME, cpu_type;
			cpu_type= "LLC";

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

			cout <<cpu_type<<" CPU:" << cpu <<"  "<< TYPE_NAME <<"  "<<setw(9)<<"set:"<<setw(4) <<dec<< set <<"   way:"<<setw(3)<< way<<" instr_num="<<instr_num2<<" secAccess:"<<LLC_secAccess[set];
			cout << hex << "   Paddr="<<(full_addr>>6)<<"  ip:"<<setw(10) << ip <<"  vPaddr="<< victim_addr<<dec<<" rrpv:"<<line_rrpv[set][way]<<" SHCT:"<<SHCT[cpu][new_sig]<<endl;
		}
	}
	
    // Stat tracking for what insertion it was at
    insertion_distrib[type][line_rrpv[set][way]]++;

}

// use this function to print out your own stats on every heartbeat 


string names[] = 
{
    "LOAD", "RFO", "PREF", "WRITEBACK", "TRANSLATIONS" 
};

// use this function to print out your own stats at the end of simulation
void CACHE::replacement_final_stats()
{
    cout<<"Insertion Distribution: "<<endl;
    for(uint32_t i=0; i<NUM_TYPES; i++) 
    {
        cout<<"\t"<<names[i]<<" ";
        for(uint32_t v=0; v<maxRRPV+1; v++) 
        {
            cout<<dec<<insertion_distrib[i][v]<<" ";
        }
        cout<<endl;
    }

    cout<<"Total Prefetch Downgrades: "<<total_prefetch_downgrades<<endl;
    
}

