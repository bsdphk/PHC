#include <stdlib.h>
#include <unistd.h>
#include "pedatabase.h"

uint32 peMemLength = 512;
uint32 peNumPebbles = 127;
uint32 peSpacingStart = UINT32_MAX;
uint32 peSpacing = 12;
uint32 peMinEdgeLength = 0; // Fix pebbles all nodes with edge length < peMinEdgeLength
uint32 peMaxInDegree = UINT32_MAX; // Fix pebbles all nodes with in-degree >= peMaxInDegree

peRoot peTheRoot;
peLocationArray peVisitedLocations;
peGroup peTheGroup;
bool peVerbose;
bool peDumpGraphs;
uint32 peMaxDegree;
uint32 peCurrentPos;
uint32 peCatenaLambda;
bool peCatena3InFirstRow;

typedef enum {
    SLIDING_WINDOW,
    RAND_CUBED,
    RAND,
    CATENA,
    SLIDING_REVERSE,
    SLIDING_CATENA,
    REVERSE
} peGraphType;

peGraphType peCurrentType;

// Return the name of the type.
char *getTypeName(peGraphType type) {
    switch(type) {
    case SLIDING_WINDOW: return "sliding_window";
    case RAND_CUBED: return "rand_cubed";
    case RAND: return "rand";
    case CATENA: return "catena";
    case SLIDING_REVERSE: return "sliding_reverse";
    case SLIDING_CATENA: return "sliding_catena";
    case REVERSE: return "reverse";
    default:
        utExit("Unknown graph type");
    }
    return NULL; // Dummy return
}

// Return the type given the name.
static peGraphType parseType(char *name) {
    if(!strcmp(name, "sliding_window")) {
        return SLIDING_WINDOW;
    }
    if(!strcasecmp(name, "rand_cubed")) {
        return RAND_CUBED;
    }
    if(!strcasecmp(name, "rand")) {
        return RAND;
    }
    if(!strcasecmp(name, "sliding_window")) {
        return SLIDING_WINDOW;
    }
    if(!strcasecmp(name, "catena")) {
        return CATENA;
    }
    if(!strcasecmp(name, "sliding_reverse")) {
        return SLIDING_REVERSE;
    }
    if(!strcasecmp(name, "sliding_catena")) {
        return SLIDING_CATENA;
    }
    if(!strcasecmp(name, "reverse")) {
        return REVERSE;
    }
    utExit("Unknown graph type %s", name);
    return RAND_CUBED;
}

// Find the previous position using Alexander's sliding power-of-two window.
static uint32 findSlidingWindowPos(uint32 pos) {
    // This is a sliding window which is the largest power of 2 < i.
    if(pos < 3) {
        return UINT32_MAX; // No edge
    }
    uint32 mask = 1;
    while(mask <= pos) {
        mask <<= 1;
    }
    mask = mask >> 1;
    return pos - mask + (rand() % (mask-1));
}

// Find the previous position using a uniform random value between 0..1, cube it, and go
// that * position back.
static uint32 findRandCubedPos(uint32 pos) {
    if(pos < 2) {
        return UINT32_MAX; // No edge
    }
    double dist = (rand()/(double)RAND_MAX);
    dist = dist*dist*dist;
    return pos - 2 - (uint32)((pos-2)*dist);
}

// Find the previous position using a uniform random value.
static uint32 findRandPos(uint32 pos) {
    if(pos < 2) {
        return UINT32_MAX; // No edge
    }
    double dist = rand()/(double)RAND_MAX;
    return pos - 2 - (uint32)((pos-2)*dist);
}

// Reverse the bits.
static uint32 bitReverse(uint32 value, uint32 rowLength) {
    //printf("rowLength:%u %x -> ", rowLength, value);
    uint32 result = 0;
    while(rowLength != 1) {
        result = (result << 1) | (value & 1);
        value >>= 1;
        rowLength >>= 1;
    }
    //printf("%x\n", result);
    return result;
}

// Find the previous position using a uniform random value between 0..1, cube it, and go
// that * position back.
static uint32 findCatenaPos(uint32 pos) {
    uint32 rowLength = peMemLength/(peCatenaLambda + 1); // Note: peMemLength/lambda must be power of 2
    uint32 row = pos/rowLength;
    if(row == 0) {
        if(!peCatena3InFirstRow || rowLength < 8) {
            return UINT32_MAX;
        }
        rowLength /= 4; // Build a Catena-3 graph in the first row
        row = pos/rowLength;
        if(row == 0) {
            return UINT32_MAX;
        }
        uint32 rowPos = pos - row*rowLength;
        return (row-1)*rowLength + bitReverse(rowPos, rowLength);
    }
    uint32 rowPos = pos - row*rowLength;
    uint32 dest = (row-1)*rowLength + bitReverse(rowPos, rowLength);
    //if(dest + rowLength + 1 < pos) {
        //return dest + rowLength;
    //}
    return dest;
}

// Find the previous position using Alexander's sliding power-of-two window, with Catena
// bit-reversal.
static uint32 findSlidingReversePos(uint32 pos) {
    // This is a sliding window which is the largest power of 2 < i.
    if(pos < 2) {
        return UINT32_MAX;
    }
    uint32 mask = 1;
    while(mask <= pos) {
        mask <<= 1;
    }
    mask = mask >> 1; // Mask is greatest power of 2 <= pos
    uint32 reversePos = bitReverse((pos) & (mask-1), mask);
    if(reversePos + 1 >= pos - mask) {
        return reversePos;
    }
    return reversePos + mask;
}

// Find the previous position using Alexander's sliding power-of-two window, with Catena
// bit-reversal, but with the sliding window 1/2 as big.
static uint32 findSlidingCatenaPos(uint32 pos) {
    // This is a sliding window which is the largest power of 2 < i.
    if(pos < 2) {
        return UINT32_MAX;
    }
    uint32 mask = 1;
    while(mask <= pos) {
        mask <<= 1;
    }
    mask = mask >> 2; // Mask is greatest power of 2 <= pos/2
    uint32 reversePos = mask + bitReverse((pos) & (mask-1), mask);
    if(reversePos + 1 + 2*mask < pos) {
        return reversePos + 2*mask;
    }
    if(reversePos + 1 + mask < pos) {
        return reversePos + mask;
    }
    return reversePos;
}

// Find the previous position using a simple rule: dest = pow2 - i, where pow2 is the
// largest power of 2 < i.
static uint32 findReversePos(uint32 pos) {
    if(pos < 3) {
        return UINT32_MAX; // No edge
    }
    uint32 mask = 1;
    while(mask <= pos) {
        mask <<= 1;
    }
    uint32 prevPos = mask - pos - 1;
    prevPos = bitReverse(prevPos, mask >> 1);
    if(prevPos + 1 >= pos) {
        return UINT32_MAX; // No edge
    }
    return prevPos;
}

// Find the previous position to point to.
static void setPrevLocation(uint32 pos, peGraphType type) {
    if(pos == 0) {
        return;
    }
    peLocation location = peRootGetiLocation(peTheRoot, pos);
    uint32 prevPos = 0;
    switch(type) {
    case SLIDING_WINDOW: prevPos = findSlidingWindowPos(pos); break;
    case RAND_CUBED: prevPos = findRandCubedPos(pos); break;
    case RAND: prevPos = findRandPos(pos); break;
    case CATENA: prevPos = findCatenaPos(pos); break;
    case SLIDING_REVERSE: prevPos = findSlidingReversePos(pos); break;
    case SLIDING_CATENA: prevPos = findSlidingCatenaPos(pos); break;
    case REVERSE: prevPos = findReversePos(pos); break;
    default:
        utExit("Unknown graph type\n");
    }
    if(prevPos == UINT32_MAX || prevPos + 1 == pos) {
        return; // No edge
    }
    peLocation prevLocation = peRootGetiLocation(peTheRoot, prevPos);
    utAssert(prevPos + 1 < pos);
    peLocationAppendLocation(prevLocation, location);
}

// Find the previous position to point to.
static inline uint32 findPrevPos(uint32 pos) {
    peLocation prevLocation = peLocationGetLocation(peRootGetiLocation(peTheRoot, pos));
    if(prevLocation == peLocationNull) {
        return 0;
    }
    return peLocationGetRootIndex(prevLocation);
}

// Dump the graph.
static void dumpGraph(void) {
    uint32 pos;
    for(pos = 0; pos < peMemLength; pos++) {
        peLocation location = peRootGetiLocation(peTheRoot, pos);
        pePebble pebble = peLocationGetPebble(location);
        char c = ' ';
        char l = ' ';
        if(peLocationGetUseCount(location) > 0) {
            if(peLocationFixed(location)) {
                l = '!';
            } else {
                l = '0' + peLocationGetUseCount(location);
            }
        }
        if(pebble != pePebbleNull) {
            c = '*';
            if(pePebbleGetGroup(pebble) != peGroupNull) {
                c = '-';
            }
        }
        if(peLocationGetLocation(location) == peLocationNull) {
            printf("%c %c n%-17u %u pointers %u\n", c, l, pos,
                peLocationGetNumPointers(location), peLocationGetRecomputations(location));
        } else {
            printf("%c %c n%-6u -> n%-6u %u pointers %u\n", c, l, pos, findPrevPos(pos),
                peLocationGetNumPointers(location), peLocationGetRecomputations(location));
        }
    }
}

// Find the number of nearest future pointer that come from the beyond the max pebble
// placement.  Return 0 if there is none.
static uint32 findNearestFuturePointer(peLocation location) {
    peLocation nextLocation;
    peForeachLocationLocation(location, nextLocation) {
        uint32 pos = peLocationGetRootIndex(nextLocation);
        if(pos > peCurrentPos) {
            return pos;
        }
    } peEndLocationLocation;
    return 0;
}

// Create a new lazy pebble group.
static void addPebblesToGroup(void) {
    uint32 numPebbles = 0;
    peLocation location;
    peForeachRootLocation(peTheRoot, location) {
        if(peLocationGetUseCount(location) == 0 && findNearestFuturePointer(location) == 0) {
            pePebble pebble = peLocationGetPebble(location);
            if(pebble != pePebbleNull) {
                peGroupAppendPebble(peTheGroup, pebble);
                numPebbles++;
            }
        }
    } peEndRootLocation;
    peGroupSetAvailablePebbles(peTheGroup, numPebbles);
    if(peVerbose) {
        printf("Rebuilt group with %u pebbles\n", numPebbles);
        dumpGraph();
    }
}

// Determine if the first pebble is better than the second.
static inline bool pebbleBetterThanPebble(pePebble pebble1, pePebble pebble2) {
    peLocation location1 = pePebbleGetLocation(pebble1);
    peLocation location2 = pePebbleGetLocation(pebble2);
    return findNearestFuturePointer(location1) > findNearestFuturePointer(location2);
}

// We are in the position of having to pick up a pebble we know we will need in the
// future.  Try to find a low-pain choice, and add it to the group.  This that make a
// choice low pain are low initial computation cost and being needed further in the
// future.
static pePebble findLeastBadPebble(void) {
    pePebble bestPebble = pePebbleNull;
    uint32 i;
    for(i = 0; i < peCurrentPos; i++) {
        peLocation location = peRootGetiLocation(peTheRoot, i);
        if(peLocationGetUseCount(location) == 0) {
            pePebble pebble = peLocationGetPebble(location);
            if(pebble != pePebbleNull) {
                if(bestPebble == pePebbleNull || pebbleBetterThanPebble(pebble, bestPebble)) {
                    bestPebble = pebble;
                }
            }
        }
    }
    if(bestPebble == pePebbleNull) {
        if(peDumpGraphs) {
            dumpGraph();
        }
        utExit("Where did all the pebbles go?");
    }
    return bestPebble;
}

// Delete all the pebbles in the group.
static void clearGroup(void) {
    pePebble pebble;
    peSafeForeachGroupPebble(peTheGroup, pebble) {
        pePebbleDestroy(pebble);
    } peEndSafeGroupPebble;
    peGroupSetAvailablePebbles(peTheGroup, 0);
}

// The group is empty, so delete all the pebbles since they have been used.  Then create a
// new group with the pebbles in the graph.  Try to build a group using the minimum degree
// possible.
static void rebuildGroup(void) {
    clearGroup();
    addPebblesToGroup();
}

// Pull a pebble from the group.  Just decrement the available counter, and return a new pebble.
static pePebble pullPebbleFromGroup(void) {
    uint32 numAvailable = peGroupGetAvailablePebbles(peTheGroup);
    peGroupSetAvailablePebbles(peTheGroup, numAvailable-1);
    if(peGroupGetAvailablePebbles(peTheGroup) == 0) {
        clearGroup();
    }
    return pePebbleAlloc();
}

// Remove the pebble from the group, since it's needed in it's current location.
static void removePebbleFromGroup(pePebble pebble) {
    uint32 numAvailable = peGroupGetAvailablePebbles(peTheGroup);
    utAssert(numAvailable > 0 && peLocationGetUseCount(pePebbleGetLocation(pebble)) == 1);
    peGroupRemovePebble(peTheGroup, pebble);
    if(numAvailable == 1) {
        clearGroup();
    } else {
        peGroupSetAvailablePebbles(peTheGroup, numAvailable-1);
    }
}

// Find a pebble that will be used as far as possible in the future, and pick it up.
static inline pePebble pickUpPebble(void) {
    pePebble pebble = pePebbleNull;
    if(peGroupGetAvailablePebbles(peTheGroup) == 0) {
        pebble = findLeastBadPebble();
        peLocationRemovePebble(pePebbleGetLocation(pebble), pebble);
        return pebble;
    }
    pebble = pullPebbleFromGroup();
    if(peVerbose) {
        printf("Picking up pebble, %u remain available\n", peGroupGetAvailablePebbles(peTheGroup));
    }
    return pebble;
}

// Place a pebble.  This causes any pebble on the fanin that had this pebble location as
// it's needed position to have to recompute it's needed position.
static void placePebble(pePebble pebble, uint32 pos) {
    utAssert(pePebbleGetGroup(pebble) == peGroupNull);
    peLocation location = peRootGetiLocation(peTheRoot, pos);
    utAssert(peLocationGetPebble(location) == pePebbleNull);
    peLocationInsertPebble(location, pebble);
    if(peVerbose) {
        printf("Placing %u\n", pos);
    }
}

// Mark the pebble in use.
static inline void markInUse(peLocation location) {
    if(!peLocationFixed(location)) {
        peLocationSetUseCount(location, peLocationGetUseCount(location) + 1);
        pePebble pebble = peLocationGetPebble(location);
        if(pebble != pePebbleNull && pePebbleGetGroup(pebble) != peGroupNull) {
            removePebbleFromGroup(pebble);
        }
    }
}

// Unmark a pabble as in use.
static inline void unmarkInUse(peLocation location) {
    if(!peLocationFixed(location)) {
        uint32 useCount = peLocationGetUseCount(location);
        utAssert(useCount != 0);
        peLocationSetUseCount(location, useCount - 1);
    }
}

// Pebble the location and return the total number of pebbles moved.
static uint32 pebbleLocation(uint32 pos) {
    peLocation location = peRootGetiLocation(peTheRoot, pos);
    pePebble pebble = peLocationGetPebble(location);
    utAssert(pebble == pePebbleNull && peLocationGetUseCount(location) >= 1);
    if(peVerbose) {
        printf("Trying to cover %u\n", pos);
    }
    peLocation prevLocation1 = peLocationNull;
    peLocation prevLocation2 = peLocationGetLocation(location);
    uint32 total = 0;
    if(pos > 0) {
        prevLocation1 = peRootGetiLocation(peTheRoot, pos-1);
        markInUse(prevLocation1);
    }
    if(prevLocation2 != peLocationNull) {
        markInUse(prevLocation2);
    }
    pePebble prev1 = pePebbleNull;
    pePebble prev2 = pePebbleNull;
    if(prevLocation1 != peLocationNull) {
        prev1 = peLocationGetPebble(prevLocation1);
        if(prev1 == pePebbleNull) {
            total += pebbleLocation(pos-1);
            prev1 = peLocationGetPebble(prevLocation1);
        }
    }
    if(prevLocation2 != peLocationNull) {
        prev2 = peLocationGetPebble(prevLocation2);
        if(prev2 == pePebbleNull) {
            // There is an odd case where pebbling prev1 creates a pebble in prev2's spot
            total += pebbleLocation(peLocationGetRootIndex(prevLocation2));
            prev2 = peLocationGetPebble(prevLocation2);
        }
    }
    if(prevLocation1 != peLocationNull) {
        unmarkInUse(prevLocation1);
    }
    if(prevLocation2 != peLocationNull) {
        unmarkInUse(prevLocation2);
    }
    if(peGroupGetAvailablePebbles(peTheGroup) == 0) {
        rebuildGroup();
    }
    pebble = pickUpPebble();
    placePebble(pebble, pos);
    if(peVerbose) {
        dumpGraph();
    }
    return total + 1;
}

// Pebble the graph with a fixed number of pebbles.  When a pebble is needed, pick up a
// pebble that currently is not needed until the maximum time in the future.
static void pebbleGraph(void) {
    peTheGroup = peGroupAlloc();
    peRootAppendGroup(peTheRoot, peTheGroup);
    peCurrentPos = peNumPebbles;
    uint64 total = peNumPebbles;
    for(; peCurrentPos < peMemLength; peCurrentPos++) {
        peLocation location = peRootGetiLocation(peTheRoot, peCurrentPos);
        markInUse(location);
        total += pebbleLocation(peCurrentPos);
        unmarkInUse(location);
    }
    printf("Recalculation penalty is %.4fX\n", 1 + total/(double)peMemLength - 1.0);
}

// Set the number of pointers to each memory location.
static void setNumPointers(peGraphType type) {
    peMaxDegree = 0;
    uint32 i;
    for(i = 1; i < peMemLength; i++) {
        setPrevLocation(i, type);
        peLocation prevLocation = peLocationGetLocation(peRootGetiLocation(peTheRoot, i));
        if(prevLocation != peLocationNull) {
            uint32 numPointers = peLocationGetNumPointers(prevLocation) + 1;
            peLocationSetNumPointers(prevLocation, numPointers);
            if(numPointers > peMaxDegree) {
                peMaxDegree = numPointers;
            }
        }
    }
}

// Set the fixed locations.
static void setFixedNodes(bool computePenalty) {
    uint32 i;
    bool fixNextLocation = false;
    for(i = 0; i < peMemLength; i++) {
        peLocation location = peRootGetiLocation(peTheRoot, i);
        if(i >= peSpacingStart && i % peSpacing == peSpacingStart) {
            // Fix the position of pebbles every so often to see if it helps.
            fixNextLocation = true;
        }
        if(peLocationGetNumPointers(location) > 0 || computePenalty) {
            peLocation prevLocation = peLocationGetFirstLocation(location);
            if(prevLocation != peLocationNull && peLocationGetRootIndex(prevLocation) - i <= peMinEdgeLength) {
                fixNextLocation = true;
            }
            if(peLocationGetNumPointers(location) >= peMaxInDegree) {
                fixNextLocation = true;
            }
            if(fixNextLocation) {
                /* It's a waset to fix pebbles on locations that aren't pointed to by anybody. */
                peLocationSetFixed(location, true);
                peLocationSetUseCount(location, 1);
                fixNextLocation = false;
            }
        }
    }
}

// Compute the cut size at the middle.
static void computeCut(void) {
    uint32 cutSize = 0;
    uint32 i;
    for(i = peMemLength/2; i < peMemLength-1; i++) {
        if(findPrevPos(i) < peMemLength/2) {
            cutSize++;
        }
    }
    printf("Mid-cut size: %u (%.1f%%)\n", cutSize, (cutSize*100.0)/peMemLength);
}

// Distribute pebbles in the first memory locations.
static void distributePebbles(void) {
    uint32 total = 0;
    uint32 xPebble;
    for(xPebble = 0; xPebble < peNumPebbles; xPebble++) {
        peLocation location = peRootGetiLocation(peTheRoot, xPebble);
        pePebble pebble = pePebbleAlloc();
        peLocationInsertPebble(location, pebble);
        total++;
    }
    printf("Total pebbles: %u out of %u (%.1f%%)\n", total, peMemLength, total*100.0/peMemLength);
}

// Find the size of the uncovered DAG starting at pos.
static uint32 findDAGSize(uint32 pos) {
    peLocation location = peRootGetiLocation(peTheRoot, pos);
    if(peLocationFixed(location) || peLocationVisited(location)) {
        return 0;
    }
    uint32 numPebbles = 1;
    peLocationSetVisited(location, true);
    peLocationArrayAppendLocation(peVisitedLocations, location);
    if(pos > 0) {
        uint32 prevPos = findPrevPos(pos);
        numPebbles += findDAGSize(prevPos);
        numPebbles += findDAGSize(pos - 1);
    }
    return numPebbles;
}

// Find the average size of the sub-DAG that has to be recomputed when I randomly ask for
// values from memory.
static void computeAveragePenalty(void) {
    uint64 total = 0;
    uint32 i;
    for(i = 0; i < peMemLength; i++) {
        peLocation location = peRootGetiLocation(peTheRoot, i);
        if(!peLocationFixed(location)) {
            uint32 recomputations = findDAGSize(i);
            peLocationSetRecomputations(location, recomputations);
            total += recomputations;
            peForeachLocationArrayLocation(peVisitedLocations, location) {
                peLocationSetVisited(location, false);
            } peEndLocationArrayLocation;
            peLocationArraySetUsedLocation(peVisitedLocations, 0);
        }
    }
    uint32 numPebbles = 0;
    for(i = 0; i < peMemLength; i++) {
        if(peLocationFixed(peRootGetiLocation(peTheRoot, i))) {
            numPebbles++;
        }
    }
    printf("Total pebbles: %f%%\n", numPebbles*100.0/peMemLength);
    printf("Recalculation penalty is %fX\n", (total + peMemLength)/(double)peMemLength);
}

// Test the type of graph.
static void runTest(peGraphType type, bool computePenalty) {
    peTheRoot = peRootAlloc();
    peVisitedLocations = peLocationArrayAlloc();
    peRootAllocLocations(peTheRoot, peMemLength);
    uint32 i;
    for(i = 0; i < peMemLength; i++) {
        peLocation location = peLocationAlloc();
        peRootInsertLocation(peTheRoot, i, location);
    }
    printf("========= Testing %s\n", getTypeName(type));
    peCurrentType = type;
    setNumPointers(type);
    setFixedNodes(computePenalty);
    if(computePenalty) {
        computeAveragePenalty();
    } else {
        distributePebbles();
        pebbleGraph();
    }
    if(peDumpGraphs) {
        dumpGraph();
    }
    computeCut();
    peRootDestroy(peTheRoot);
    printf("\n");
}

// Usage
static void usage(void) {
    fprintf(stderr, "usage: pebble [OPTIONS] [DAG type]\n"
        "    -c                -- compute average recomputation penalty\n"
        "    -d minDegree      -- fix pebbles on nodes with in degree >= minDegree\n"
        "    -g                -- dump graph\n"
        "    -m memLength      -- size of DAG size to use (defaults to 512)\n"
        "    -l maxLength      -- fix pebbles pointed to by edge <= maxLength\n"
        "    -L lambda         -- set Catena lambda\n"
        "    -p numPebbles     -- pebble the graph using at most numPebbles pebbles\n"
        "    -r                -- enable sub-Catena3 graph in Catena first row\n"
        "    -s spacing        -- fix pebbles every spacing pebbles\n"
        "    -t startSpacing   -- Start pebble spacing at startSpacing node\n"
        "    -v                -- verbose mode\n");
    fprintf(stderr, "graph types:");
    uint32 i;
    for(i = 0; i <= REVERSE; i++) {
        fprintf(stderr, " %s", getTypeName(i));
    }
    fprintf(stderr, "\n");
    exit(1);
}

int main(int argc, char **argv) {
    peDumpGraphs = false;
    peVerbose = false;
    peCatenaLambda = 3;
    peCatena3InFirstRow = false;
    bool computePenalty = false;

    char c;
    while((c = getopt(argc, argv, "cd:gm:l:L:p:rs:t:v")) != -1) {
        switch (c) {
        case 'c':
            computePenalty = true;
        case 'g':
            peDumpGraphs = true;
            break;
        case 'v':
            peDumpGraphs = true;
            peVerbose = true;
            break;
        case 'm':
            peMemLength = atoi(optarg);
            if(peNumPebbles > peMemLength) {
                peNumPebbles = peMemLength >> 1;
            }
            break;
        case 'p':
            peNumPebbles = atoi(optarg);
            break;
        case 's':
            peSpacing = atoi(optarg);
            if(peSpacingStart == UINT32_MAX) {
                peSpacingStart = peSpacing - 1;
            }
            break;
        case 't':
            peSpacingStart = atoi(optarg);
            break;
        case 'L':
            peCatenaLambda = atoi(optarg);
            break;
        case 'l':
            peMinEdgeLength = atoi(optarg);
            break;
        case 'r':
            peCatena3InFirstRow = true;
            break;
        case 'd':
            peMaxInDegree = atoi(optarg);
            break;
        default:
            usage();
        }
    }
    utStart();
    peDatabaseStart();
    if(optind < argc - 1) {
        fprintf(stderr, "Too many parameters\n");
        usage();
    } else if(optind + 1 == argc) {
        runTest(parseType(argv[optind]), computePenalty);
    } else {
        uint32 type;
        for(type = 0; type <= REVERSE; type++) {
            runTest(type, computePenalty);
        }
    }
    peDatabaseStop();
    utStop(true);
    return 0;
}
