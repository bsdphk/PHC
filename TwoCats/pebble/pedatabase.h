/*----------------------------------------------------------------------------------------
  Module header file for: pe module
----------------------------------------------------------------------------------------*/
#ifndef PEDATABASE_H

#define PEDATABASE_H

#if defined __cplusplus
extern "C" {
#endif

#ifndef DD_UTIL_H
#include "ddutil.h"
#endif

extern uint8 peModuleID;
/* Class reference definitions */
#if (defined(DD_DEBUG) && !defined(DD_NOSTRICT)) || defined(DD_STRICT)
typedef struct _struct_peRoot{char val;} *peRoot;
#define peRootNull ((peRoot)0)
typedef struct _struct_pePebble{char val;} *pePebble;
#define pePebbleNull ((pePebble)0)
typedef struct _struct_peLocation{char val;} *peLocation;
#define peLocationNull ((peLocation)0)
typedef struct _struct_peGroup{char val;} *peGroup;
#define peGroupNull ((peGroup)0)
typedef struct _struct_peLocationArray{char val;} *peLocationArray;
#define peLocationArrayNull ((peLocationArray)0)
#else
typedef uint32 peRoot;
#define peRootNull 0
typedef uint32 pePebble;
#define pePebbleNull 0
typedef uint32 peLocation;
#define peLocationNull 0
typedef uint32 peGroup;
#define peGroupNull 0
typedef uint32 peLocationArray;
#define peLocationArrayNull 0
#endif

/* Constructor/Destructor hooks. */
typedef void (*peRootCallbackType)(peRoot);
extern peRootCallbackType peRootConstructorCallback;
extern peRootCallbackType peRootDestructorCallback;
typedef void (*pePebbleCallbackType)(pePebble);
extern pePebbleCallbackType pePebbleConstructorCallback;
extern pePebbleCallbackType pePebbleDestructorCallback;
typedef void (*peLocationCallbackType)(peLocation);
extern peLocationCallbackType peLocationConstructorCallback;
extern peLocationCallbackType peLocationDestructorCallback;
typedef void (*peGroupCallbackType)(peGroup);
extern peGroupCallbackType peGroupConstructorCallback;
extern peGroupCallbackType peGroupDestructorCallback;
typedef void (*peLocationArrayCallbackType)(peLocationArray);
extern peLocationArrayCallbackType peLocationArrayConstructorCallback;
extern peLocationArrayCallbackType peLocationArrayDestructorCallback;

/*----------------------------------------------------------------------------------------
  Root structure
----------------------------------------------------------------------------------------*/
struct peRootType_ {
    uint32 hash; /* This depends only on the structure of the database */
    peRoot firstFreeRoot;
    uint32 usedRoot, allocatedRoot;
    uint32 usedRootLocation, allocatedRootLocation, freeRootLocation;
    pePebble firstFreePebble;
    uint32 usedPebble, allocatedPebble;
    peLocation firstFreeLocation;
    uint32 usedLocation, allocatedLocation;
    peGroup firstFreeGroup;
    uint32 usedGroup, allocatedGroup;
    peLocationArray firstFreeLocationArray;
    uint32 usedLocationArray, allocatedLocationArray;
    uint32 usedLocationArrayLocation, allocatedLocationArrayLocation, freeLocationArrayLocation;
};
extern struct peRootType_ peRootData;

utInlineC uint32 peHash(void) {return peRootData.hash;}
utInlineC peRoot peFirstFreeRoot(void) {return peRootData.firstFreeRoot;}
utInlineC void peSetFirstFreeRoot(peRoot value) {peRootData.firstFreeRoot = (value);}
utInlineC uint32 peUsedRoot(void) {return peRootData.usedRoot;}
utInlineC uint32 peAllocatedRoot(void) {return peRootData.allocatedRoot;}
utInlineC void peSetUsedRoot(uint32 value) {peRootData.usedRoot = value;}
utInlineC void peSetAllocatedRoot(uint32 value) {peRootData.allocatedRoot = value;}
utInlineC uint32 peUsedRootLocation(void) {return peRootData.usedRootLocation;}
utInlineC uint32 peAllocatedRootLocation(void) {return peRootData.allocatedRootLocation;}
utInlineC uint32 peFreeRootLocation(void) {return peRootData.freeRootLocation;}
utInlineC void peSetUsedRootLocation(uint32 value) {peRootData.usedRootLocation = value;}
utInlineC void peSetAllocatedRootLocation(uint32 value) {peRootData.allocatedRootLocation = value;}
utInlineC void peSetFreeRootLocation(int32 value) {peRootData.freeRootLocation = value;}
utInlineC pePebble peFirstFreePebble(void) {return peRootData.firstFreePebble;}
utInlineC void peSetFirstFreePebble(pePebble value) {peRootData.firstFreePebble = (value);}
utInlineC uint32 peUsedPebble(void) {return peRootData.usedPebble;}
utInlineC uint32 peAllocatedPebble(void) {return peRootData.allocatedPebble;}
utInlineC void peSetUsedPebble(uint32 value) {peRootData.usedPebble = value;}
utInlineC void peSetAllocatedPebble(uint32 value) {peRootData.allocatedPebble = value;}
utInlineC peLocation peFirstFreeLocation(void) {return peRootData.firstFreeLocation;}
utInlineC void peSetFirstFreeLocation(peLocation value) {peRootData.firstFreeLocation = (value);}
utInlineC uint32 peUsedLocation(void) {return peRootData.usedLocation;}
utInlineC uint32 peAllocatedLocation(void) {return peRootData.allocatedLocation;}
utInlineC void peSetUsedLocation(uint32 value) {peRootData.usedLocation = value;}
utInlineC void peSetAllocatedLocation(uint32 value) {peRootData.allocatedLocation = value;}
utInlineC peGroup peFirstFreeGroup(void) {return peRootData.firstFreeGroup;}
utInlineC void peSetFirstFreeGroup(peGroup value) {peRootData.firstFreeGroup = (value);}
utInlineC uint32 peUsedGroup(void) {return peRootData.usedGroup;}
utInlineC uint32 peAllocatedGroup(void) {return peRootData.allocatedGroup;}
utInlineC void peSetUsedGroup(uint32 value) {peRootData.usedGroup = value;}
utInlineC void peSetAllocatedGroup(uint32 value) {peRootData.allocatedGroup = value;}
utInlineC peLocationArray peFirstFreeLocationArray(void) {return peRootData.firstFreeLocationArray;}
utInlineC void peSetFirstFreeLocationArray(peLocationArray value) {peRootData.firstFreeLocationArray = (value);}
utInlineC uint32 peUsedLocationArray(void) {return peRootData.usedLocationArray;}
utInlineC uint32 peAllocatedLocationArray(void) {return peRootData.allocatedLocationArray;}
utInlineC void peSetUsedLocationArray(uint32 value) {peRootData.usedLocationArray = value;}
utInlineC void peSetAllocatedLocationArray(uint32 value) {peRootData.allocatedLocationArray = value;}
utInlineC uint32 peUsedLocationArrayLocation(void) {return peRootData.usedLocationArrayLocation;}
utInlineC uint32 peAllocatedLocationArrayLocation(void) {return peRootData.allocatedLocationArrayLocation;}
utInlineC uint32 peFreeLocationArrayLocation(void) {return peRootData.freeLocationArrayLocation;}
utInlineC void peSetUsedLocationArrayLocation(uint32 value) {peRootData.usedLocationArrayLocation = value;}
utInlineC void peSetAllocatedLocationArrayLocation(uint32 value) {peRootData.allocatedLocationArrayLocation = value;}
utInlineC void peSetFreeLocationArrayLocation(int32 value) {peRootData.freeLocationArrayLocation = value;}

/* Validate macros */
#if defined(DD_DEBUG)
utInlineC peRoot peValidRoot(peRoot Root) {
    utAssert(utLikely(Root != peRootNull && (uint32)(Root - (peRoot)0) < peRootData.usedRoot));
    return Root;}
utInlineC pePebble peValidPebble(pePebble Pebble) {
    utAssert(utLikely(Pebble != pePebbleNull && (uint32)(Pebble - (pePebble)0) < peRootData.usedPebble));
    return Pebble;}
utInlineC peLocation peValidLocation(peLocation Location) {
    utAssert(utLikely(Location != peLocationNull && (uint32)(Location - (peLocation)0) < peRootData.usedLocation));
    return Location;}
utInlineC peGroup peValidGroup(peGroup Group) {
    utAssert(utLikely(Group != peGroupNull && (uint32)(Group - (peGroup)0) < peRootData.usedGroup));
    return Group;}
utInlineC peLocationArray peValidLocationArray(peLocationArray LocationArray) {
    utAssert(utLikely(LocationArray != peLocationArrayNull && (uint32)(LocationArray - (peLocationArray)0) < peRootData.usedLocationArray));
    return LocationArray;}
#else
utInlineC peRoot peValidRoot(peRoot Root) {return Root;}
utInlineC pePebble peValidPebble(pePebble Pebble) {return Pebble;}
utInlineC peLocation peValidLocation(peLocation Location) {return Location;}
utInlineC peGroup peValidGroup(peGroup Group) {return Group;}
utInlineC peLocationArray peValidLocationArray(peLocationArray LocationArray) {return LocationArray;}
#endif

/* Object ref to integer conversions */
#if (defined(DD_DEBUG) && !defined(DD_NOSTRICT)) || defined(DD_STRICT)
utInlineC uint32 peRoot2Index(peRoot Root) {return Root - (peRoot)0;}
utInlineC uint32 peRoot2ValidIndex(peRoot Root) {return peValidRoot(Root) - (peRoot)0;}
utInlineC peRoot peIndex2Root(uint32 xRoot) {return (peRoot)(xRoot + (peRoot)(0));}
utInlineC uint32 pePebble2Index(pePebble Pebble) {return Pebble - (pePebble)0;}
utInlineC uint32 pePebble2ValidIndex(pePebble Pebble) {return peValidPebble(Pebble) - (pePebble)0;}
utInlineC pePebble peIndex2Pebble(uint32 xPebble) {return (pePebble)(xPebble + (pePebble)(0));}
utInlineC uint32 peLocation2Index(peLocation Location) {return Location - (peLocation)0;}
utInlineC uint32 peLocation2ValidIndex(peLocation Location) {return peValidLocation(Location) - (peLocation)0;}
utInlineC peLocation peIndex2Location(uint32 xLocation) {return (peLocation)(xLocation + (peLocation)(0));}
utInlineC uint32 peGroup2Index(peGroup Group) {return Group - (peGroup)0;}
utInlineC uint32 peGroup2ValidIndex(peGroup Group) {return peValidGroup(Group) - (peGroup)0;}
utInlineC peGroup peIndex2Group(uint32 xGroup) {return (peGroup)(xGroup + (peGroup)(0));}
utInlineC uint32 peLocationArray2Index(peLocationArray LocationArray) {return LocationArray - (peLocationArray)0;}
utInlineC uint32 peLocationArray2ValidIndex(peLocationArray LocationArray) {return peValidLocationArray(LocationArray) - (peLocationArray)0;}
utInlineC peLocationArray peIndex2LocationArray(uint32 xLocationArray) {return (peLocationArray)(xLocationArray + (peLocationArray)(0));}
#else
utInlineC uint32 peRoot2Index(peRoot Root) {return Root;}
utInlineC uint32 peRoot2ValidIndex(peRoot Root) {return peValidRoot(Root);}
utInlineC peRoot peIndex2Root(uint32 xRoot) {return xRoot;}
utInlineC uint32 pePebble2Index(pePebble Pebble) {return Pebble;}
utInlineC uint32 pePebble2ValidIndex(pePebble Pebble) {return peValidPebble(Pebble);}
utInlineC pePebble peIndex2Pebble(uint32 xPebble) {return xPebble;}
utInlineC uint32 peLocation2Index(peLocation Location) {return Location;}
utInlineC uint32 peLocation2ValidIndex(peLocation Location) {return peValidLocation(Location);}
utInlineC peLocation peIndex2Location(uint32 xLocation) {return xLocation;}
utInlineC uint32 peGroup2Index(peGroup Group) {return Group;}
utInlineC uint32 peGroup2ValidIndex(peGroup Group) {return peValidGroup(Group);}
utInlineC peGroup peIndex2Group(uint32 xGroup) {return xGroup;}
utInlineC uint32 peLocationArray2Index(peLocationArray LocationArray) {return LocationArray;}
utInlineC uint32 peLocationArray2ValidIndex(peLocationArray LocationArray) {return peValidLocationArray(LocationArray);}
utInlineC peLocationArray peIndex2LocationArray(uint32 xLocationArray) {return xLocationArray;}
#endif

/*----------------------------------------------------------------------------------------
  Fields for class Root.
----------------------------------------------------------------------------------------*/
struct peRootFields {
    uint32 *LocationIndex_;
    uint32 *NumLocation;
    peLocation *Location;
    uint32 *UsedLocation;
    peGroup *FirstGroup;
    peGroup *LastGroup;
};
extern struct peRootFields peRoots;

void peRootAllocMore(void);
void peRootCopyProps(peRoot peOldRoot, peRoot peNewRoot);
void peRootAllocLocations(peRoot Root, uint32 numLocations);
void peRootResizeLocations(peRoot Root, uint32 numLocations);
void peRootFreeLocations(peRoot Root);
void peCompactRootLocations(void);
utInlineC uint32 peRootGetLocationIndex_(peRoot Root) {return peRoots.LocationIndex_[peRoot2ValidIndex(Root)];}
utInlineC void peRootSetLocationIndex_(peRoot Root, uint32 value) {peRoots.LocationIndex_[peRoot2ValidIndex(Root)] = value;}
utInlineC uint32 peRootGetNumLocation(peRoot Root) {return peRoots.NumLocation[peRoot2ValidIndex(Root)];}
utInlineC void peRootSetNumLocation(peRoot Root, uint32 value) {peRoots.NumLocation[peRoot2ValidIndex(Root)] = value;}
#if defined(DD_DEBUG)
utInlineC uint32 peRootCheckLocationIndex(peRoot Root, uint32 x) {utAssert(x < peRootGetNumLocation(Root)); return x;}
#else
utInlineC uint32 peRootCheckLocationIndex(peRoot Root, uint32 x) {return x;}
#endif
utInlineC peLocation peRootGetiLocation(peRoot Root, uint32 x) {return peRoots.Location[
    peRootGetLocationIndex_(Root) + peRootCheckLocationIndex(Root, x)];}
utInlineC peLocation *peRootGetLocation(peRoot Root) {return peRoots.Location + peRootGetLocationIndex_(Root);}
#define peRootGetLocations peRootGetLocation
utInlineC void peRootSetLocation(peRoot Root, peLocation *valuePtr, uint32 numLocation) {
    peRootResizeLocations(Root, numLocation);
    memcpy(peRootGetLocations(Root), valuePtr, numLocation*sizeof(peLocation));}
utInlineC void peRootSetiLocation(peRoot Root, uint32 x, peLocation value) {
    peRoots.Location[peRootGetLocationIndex_(Root) + peRootCheckLocationIndex(Root, (x))] = value;}
utInlineC uint32 peRootGetUsedLocation(peRoot Root) {return peRoots.UsedLocation[peRoot2ValidIndex(Root)];}
utInlineC void peRootSetUsedLocation(peRoot Root, uint32 value) {peRoots.UsedLocation[peRoot2ValidIndex(Root)] = value;}
utInlineC peGroup peRootGetFirstGroup(peRoot Root) {return peRoots.FirstGroup[peRoot2ValidIndex(Root)];}
utInlineC void peRootSetFirstGroup(peRoot Root, peGroup value) {peRoots.FirstGroup[peRoot2ValidIndex(Root)] = value;}
utInlineC peGroup peRootGetLastGroup(peRoot Root) {return peRoots.LastGroup[peRoot2ValidIndex(Root)];}
utInlineC void peRootSetLastGroup(peRoot Root, peGroup value) {peRoots.LastGroup[peRoot2ValidIndex(Root)] = value;}
utInlineC void peRootSetConstructorCallback(void(*func)(peRoot)) {peRootConstructorCallback = func;}
utInlineC peRootCallbackType peRootGetConstructorCallback(void) {return peRootConstructorCallback;}
utInlineC void peRootSetDestructorCallback(void(*func)(peRoot)) {peRootDestructorCallback = func;}
utInlineC peRootCallbackType peRootGetDestructorCallback(void) {return peRootDestructorCallback;}
utInlineC peRoot peRootNextFree(peRoot Root) {return ((peRoot *)(void *)(peRoots.FirstGroup))[peRoot2ValidIndex(Root)];}
utInlineC void peRootSetNextFree(peRoot Root, peRoot value) {
    ((peRoot *)(void *)(peRoots.FirstGroup))[peRoot2ValidIndex(Root)] = value;}
utInlineC void peRootFree(peRoot Root) {
    peRootFreeLocations(Root);
    peRootSetNextFree(Root, peRootData.firstFreeRoot);
    peSetFirstFreeRoot(Root);}
void peRootDestroy(peRoot Root);
utInlineC peRoot peRootAllocRaw(void) {
    peRoot Root;
    if(peRootData.firstFreeRoot != peRootNull) {
        Root = peRootData.firstFreeRoot;
        peSetFirstFreeRoot(peRootNextFree(Root));
    } else {
        if(peRootData.usedRoot == peRootData.allocatedRoot) {
            peRootAllocMore();
        }
        Root = peIndex2Root(peRootData.usedRoot);
        peSetUsedRoot(peUsedRoot() + 1);
    }
    return Root;}
utInlineC peRoot peRootAlloc(void) {
    peRoot Root = peRootAllocRaw();
    peRootSetLocationIndex_(Root, 0);
    peRootSetNumLocation(Root, 0);
    peRootSetNumLocation(Root, 0);
    peRootSetUsedLocation(Root, 0);
    peRootSetFirstGroup(Root, peGroupNull);
    peRootSetLastGroup(Root, peGroupNull);
    if(peRootConstructorCallback != NULL) {
        peRootConstructorCallback(Root);
    }
    return Root;}

/*----------------------------------------------------------------------------------------
  Fields for class Pebble.
----------------------------------------------------------------------------------------*/
struct pePebbleFields {
    peLocation *Location;
    peGroup *Group;
    pePebble *NextGroupPebble;
    pePebble *PrevGroupPebble;
};
extern struct pePebbleFields pePebbles;

void pePebbleAllocMore(void);
void pePebbleCopyProps(pePebble peOldPebble, pePebble peNewPebble);
utInlineC peLocation pePebbleGetLocation(pePebble Pebble) {return pePebbles.Location[pePebble2ValidIndex(Pebble)];}
utInlineC void pePebbleSetLocation(pePebble Pebble, peLocation value) {pePebbles.Location[pePebble2ValidIndex(Pebble)] = value;}
utInlineC peGroup pePebbleGetGroup(pePebble Pebble) {return pePebbles.Group[pePebble2ValidIndex(Pebble)];}
utInlineC void pePebbleSetGroup(pePebble Pebble, peGroup value) {pePebbles.Group[pePebble2ValidIndex(Pebble)] = value;}
utInlineC pePebble pePebbleGetNextGroupPebble(pePebble Pebble) {return pePebbles.NextGroupPebble[pePebble2ValidIndex(Pebble)];}
utInlineC void pePebbleSetNextGroupPebble(pePebble Pebble, pePebble value) {pePebbles.NextGroupPebble[pePebble2ValidIndex(Pebble)] = value;}
utInlineC pePebble pePebbleGetPrevGroupPebble(pePebble Pebble) {return pePebbles.PrevGroupPebble[pePebble2ValidIndex(Pebble)];}
utInlineC void pePebbleSetPrevGroupPebble(pePebble Pebble, pePebble value) {pePebbles.PrevGroupPebble[pePebble2ValidIndex(Pebble)] = value;}
utInlineC void pePebbleSetConstructorCallback(void(*func)(pePebble)) {pePebbleConstructorCallback = func;}
utInlineC pePebbleCallbackType pePebbleGetConstructorCallback(void) {return pePebbleConstructorCallback;}
utInlineC void pePebbleSetDestructorCallback(void(*func)(pePebble)) {pePebbleDestructorCallback = func;}
utInlineC pePebbleCallbackType pePebbleGetDestructorCallback(void) {return pePebbleDestructorCallback;}
utInlineC pePebble pePebbleNextFree(pePebble Pebble) {return ((pePebble *)(void *)(pePebbles.Location))[pePebble2ValidIndex(Pebble)];}
utInlineC void pePebbleSetNextFree(pePebble Pebble, pePebble value) {
    ((pePebble *)(void *)(pePebbles.Location))[pePebble2ValidIndex(Pebble)] = value;}
utInlineC void pePebbleFree(pePebble Pebble) {
    pePebbleSetNextFree(Pebble, peRootData.firstFreePebble);
    peSetFirstFreePebble(Pebble);}
void pePebbleDestroy(pePebble Pebble);
utInlineC pePebble pePebbleAllocRaw(void) {
    pePebble Pebble;
    if(peRootData.firstFreePebble != pePebbleNull) {
        Pebble = peRootData.firstFreePebble;
        peSetFirstFreePebble(pePebbleNextFree(Pebble));
    } else {
        if(peRootData.usedPebble == peRootData.allocatedPebble) {
            pePebbleAllocMore();
        }
        Pebble = peIndex2Pebble(peRootData.usedPebble);
        peSetUsedPebble(peUsedPebble() + 1);
    }
    return Pebble;}
utInlineC pePebble pePebbleAlloc(void) {
    pePebble Pebble = pePebbleAllocRaw();
    pePebbleSetLocation(Pebble, peLocationNull);
    pePebbleSetGroup(Pebble, peGroupNull);
    pePebbleSetNextGroupPebble(Pebble, pePebbleNull);
    pePebbleSetPrevGroupPebble(Pebble, pePebbleNull);
    if(pePebbleConstructorCallback != NULL) {
        pePebbleConstructorCallback(Pebble);
    }
    return Pebble;}

/*----------------------------------------------------------------------------------------
  Fields for class Location.
----------------------------------------------------------------------------------------*/
struct peLocationFields {
    uint32 *NumPointers;
    uint32 *Recomputations;
    uint8 *UseCount;
    uint8 *Fixed;
    uint8 *Visited;
    peRoot *Root;
    uint32 *RootIndex;
    pePebble *Pebble;
    peLocation *Location;
    peLocation *FirstLocation;
    peLocation *NextLocationLocation;
    peLocation *LastLocation;
    peLocation *PrevLocationLocation;
};
extern struct peLocationFields peLocations;

void peLocationAllocMore(void);
void peLocationCopyProps(peLocation peOldLocation, peLocation peNewLocation);
utInlineC uint32 peLocationGetNumPointers(peLocation Location) {return peLocations.NumPointers[peLocation2ValidIndex(Location)];}
utInlineC void peLocationSetNumPointers(peLocation Location, uint32 value) {peLocations.NumPointers[peLocation2ValidIndex(Location)] = value;}
utInlineC uint32 peLocationGetRecomputations(peLocation Location) {return peLocations.Recomputations[peLocation2ValidIndex(Location)];}
utInlineC void peLocationSetRecomputations(peLocation Location, uint32 value) {peLocations.Recomputations[peLocation2ValidIndex(Location)] = value;}
utInlineC uint8 peLocationGetUseCount(peLocation Location) {return peLocations.UseCount[peLocation2ValidIndex(Location)];}
utInlineC void peLocationSetUseCount(peLocation Location, uint8 value) {peLocations.UseCount[peLocation2ValidIndex(Location)] = value;}
utInlineC uint8 peLocationFixed(peLocation Location) {return peLocations.Fixed[peLocation2ValidIndex(Location)];}
utInlineC void peLocationSetFixed(peLocation Location, uint8 value) {peLocations.Fixed[peLocation2ValidIndex(Location)] = value;}
utInlineC uint8 peLocationVisited(peLocation Location) {return peLocations.Visited[peLocation2ValidIndex(Location)];}
utInlineC void peLocationSetVisited(peLocation Location, uint8 value) {peLocations.Visited[peLocation2ValidIndex(Location)] = value;}
utInlineC peRoot peLocationGetRoot(peLocation Location) {return peLocations.Root[peLocation2ValidIndex(Location)];}
utInlineC void peLocationSetRoot(peLocation Location, peRoot value) {peLocations.Root[peLocation2ValidIndex(Location)] = value;}
utInlineC uint32 peLocationGetRootIndex(peLocation Location) {return peLocations.RootIndex[peLocation2ValidIndex(Location)];}
utInlineC void peLocationSetRootIndex(peLocation Location, uint32 value) {peLocations.RootIndex[peLocation2ValidIndex(Location)] = value;}
utInlineC pePebble peLocationGetPebble(peLocation Location) {return peLocations.Pebble[peLocation2ValidIndex(Location)];}
utInlineC void peLocationSetPebble(peLocation Location, pePebble value) {peLocations.Pebble[peLocation2ValidIndex(Location)] = value;}
utInlineC peLocation peLocationGetLocation(peLocation Location) {return peLocations.Location[peLocation2ValidIndex(Location)];}
utInlineC void peLocationSetLocation(peLocation Location, peLocation value) {peLocations.Location[peLocation2ValidIndex(Location)] = value;}
utInlineC peLocation peLocationGetFirstLocation(peLocation Location) {return peLocations.FirstLocation[peLocation2ValidIndex(Location)];}
utInlineC void peLocationSetFirstLocation(peLocation Location, peLocation value) {peLocations.FirstLocation[peLocation2ValidIndex(Location)] = value;}
utInlineC peLocation peLocationGetNextLocationLocation(peLocation Location) {return peLocations.NextLocationLocation[peLocation2ValidIndex(Location)];}
utInlineC void peLocationSetNextLocationLocation(peLocation Location, peLocation value) {peLocations.NextLocationLocation[peLocation2ValidIndex(Location)] = value;}
utInlineC peLocation peLocationGetLastLocation(peLocation Location) {return peLocations.LastLocation[peLocation2ValidIndex(Location)];}
utInlineC void peLocationSetLastLocation(peLocation Location, peLocation value) {peLocations.LastLocation[peLocation2ValidIndex(Location)] = value;}
utInlineC peLocation peLocationGetPrevLocationLocation(peLocation Location) {return peLocations.PrevLocationLocation[peLocation2ValidIndex(Location)];}
utInlineC void peLocationSetPrevLocationLocation(peLocation Location, peLocation value) {peLocations.PrevLocationLocation[peLocation2ValidIndex(Location)] = value;}
utInlineC void peLocationSetConstructorCallback(void(*func)(peLocation)) {peLocationConstructorCallback = func;}
utInlineC peLocationCallbackType peLocationGetConstructorCallback(void) {return peLocationConstructorCallback;}
utInlineC void peLocationSetDestructorCallback(void(*func)(peLocation)) {peLocationDestructorCallback = func;}
utInlineC peLocationCallbackType peLocationGetDestructorCallback(void) {return peLocationDestructorCallback;}
utInlineC peLocation peLocationNextFree(peLocation Location) {return ((peLocation *)(void *)(peLocations.Root))[peLocation2ValidIndex(Location)];}
utInlineC void peLocationSetNextFree(peLocation Location, peLocation value) {
    ((peLocation *)(void *)(peLocations.Root))[peLocation2ValidIndex(Location)] = value;}
utInlineC void peLocationFree(peLocation Location) {
    peLocationSetNextFree(Location, peRootData.firstFreeLocation);
    peSetFirstFreeLocation(Location);}
void peLocationDestroy(peLocation Location);
utInlineC peLocation peLocationAllocRaw(void) {
    peLocation Location;
    if(peRootData.firstFreeLocation != peLocationNull) {
        Location = peRootData.firstFreeLocation;
        peSetFirstFreeLocation(peLocationNextFree(Location));
    } else {
        if(peRootData.usedLocation == peRootData.allocatedLocation) {
            peLocationAllocMore();
        }
        Location = peIndex2Location(peRootData.usedLocation);
        peSetUsedLocation(peUsedLocation() + 1);
    }
    return Location;}
utInlineC peLocation peLocationAlloc(void) {
    peLocation Location = peLocationAllocRaw();
    peLocationSetNumPointers(Location, 0);
    peLocationSetRecomputations(Location, 0);
    peLocationSetUseCount(Location, 0);
    peLocationSetFixed(Location, 0);
    peLocationSetVisited(Location, 0);
    peLocationSetRoot(Location, peRootNull);
    peLocationSetRootIndex(Location, UINT32_MAX);
    peLocationSetPebble(Location, pePebbleNull);
    peLocationSetLocation(Location, peLocationNull);
    peLocationSetFirstLocation(Location, peLocationNull);
    peLocationSetNextLocationLocation(Location, peLocationNull);
    peLocationSetLastLocation(Location, peLocationNull);
    peLocationSetPrevLocationLocation(Location, peLocationNull);
    if(peLocationConstructorCallback != NULL) {
        peLocationConstructorCallback(Location);
    }
    return Location;}

/*----------------------------------------------------------------------------------------
  Fields for class Group.
----------------------------------------------------------------------------------------*/
struct peGroupFields {
    uint32 *AvailablePebbles;
    peRoot *Root;
    peGroup *NextRootGroup;
    peGroup *PrevRootGroup;
    pePebble *FirstPebble;
    pePebble *LastPebble;
};
extern struct peGroupFields peGroups;

void peGroupAllocMore(void);
void peGroupCopyProps(peGroup peOldGroup, peGroup peNewGroup);
utInlineC uint32 peGroupGetAvailablePebbles(peGroup Group) {return peGroups.AvailablePebbles[peGroup2ValidIndex(Group)];}
utInlineC void peGroupSetAvailablePebbles(peGroup Group, uint32 value) {peGroups.AvailablePebbles[peGroup2ValidIndex(Group)] = value;}
utInlineC peRoot peGroupGetRoot(peGroup Group) {return peGroups.Root[peGroup2ValidIndex(Group)];}
utInlineC void peGroupSetRoot(peGroup Group, peRoot value) {peGroups.Root[peGroup2ValidIndex(Group)] = value;}
utInlineC peGroup peGroupGetNextRootGroup(peGroup Group) {return peGroups.NextRootGroup[peGroup2ValidIndex(Group)];}
utInlineC void peGroupSetNextRootGroup(peGroup Group, peGroup value) {peGroups.NextRootGroup[peGroup2ValidIndex(Group)] = value;}
utInlineC peGroup peGroupGetPrevRootGroup(peGroup Group) {return peGroups.PrevRootGroup[peGroup2ValidIndex(Group)];}
utInlineC void peGroupSetPrevRootGroup(peGroup Group, peGroup value) {peGroups.PrevRootGroup[peGroup2ValidIndex(Group)] = value;}
utInlineC pePebble peGroupGetFirstPebble(peGroup Group) {return peGroups.FirstPebble[peGroup2ValidIndex(Group)];}
utInlineC void peGroupSetFirstPebble(peGroup Group, pePebble value) {peGroups.FirstPebble[peGroup2ValidIndex(Group)] = value;}
utInlineC pePebble peGroupGetLastPebble(peGroup Group) {return peGroups.LastPebble[peGroup2ValidIndex(Group)];}
utInlineC void peGroupSetLastPebble(peGroup Group, pePebble value) {peGroups.LastPebble[peGroup2ValidIndex(Group)] = value;}
utInlineC void peGroupSetConstructorCallback(void(*func)(peGroup)) {peGroupConstructorCallback = func;}
utInlineC peGroupCallbackType peGroupGetConstructorCallback(void) {return peGroupConstructorCallback;}
utInlineC void peGroupSetDestructorCallback(void(*func)(peGroup)) {peGroupDestructorCallback = func;}
utInlineC peGroupCallbackType peGroupGetDestructorCallback(void) {return peGroupDestructorCallback;}
utInlineC peGroup peGroupNextFree(peGroup Group) {return ((peGroup *)(void *)(peGroups.Root))[peGroup2ValidIndex(Group)];}
utInlineC void peGroupSetNextFree(peGroup Group, peGroup value) {
    ((peGroup *)(void *)(peGroups.Root))[peGroup2ValidIndex(Group)] = value;}
utInlineC void peGroupFree(peGroup Group) {
    peGroupSetNextFree(Group, peRootData.firstFreeGroup);
    peSetFirstFreeGroup(Group);}
void peGroupDestroy(peGroup Group);
utInlineC peGroup peGroupAllocRaw(void) {
    peGroup Group;
    if(peRootData.firstFreeGroup != peGroupNull) {
        Group = peRootData.firstFreeGroup;
        peSetFirstFreeGroup(peGroupNextFree(Group));
    } else {
        if(peRootData.usedGroup == peRootData.allocatedGroup) {
            peGroupAllocMore();
        }
        Group = peIndex2Group(peRootData.usedGroup);
        peSetUsedGroup(peUsedGroup() + 1);
    }
    return Group;}
utInlineC peGroup peGroupAlloc(void) {
    peGroup Group = peGroupAllocRaw();
    peGroupSetAvailablePebbles(Group, 0);
    peGroupSetRoot(Group, peRootNull);
    peGroupSetNextRootGroup(Group, peGroupNull);
    peGroupSetPrevRootGroup(Group, peGroupNull);
    peGroupSetFirstPebble(Group, pePebbleNull);
    peGroupSetLastPebble(Group, pePebbleNull);
    if(peGroupConstructorCallback != NULL) {
        peGroupConstructorCallback(Group);
    }
    return Group;}

/*----------------------------------------------------------------------------------------
  Fields for class LocationArray.
----------------------------------------------------------------------------------------*/
struct peLocationArrayFields {
    uint32 *LocationIndex_;
    uint32 *NumLocation;
    peLocation *Location;
    uint32 *UsedLocation;
    peLocationArray *FreeList;
};
extern struct peLocationArrayFields peLocationArrays;

void peLocationArrayAllocMore(void);
void peLocationArrayCopyProps(peLocationArray peOldLocationArray, peLocationArray peNewLocationArray);
void peLocationArrayAllocLocations(peLocationArray LocationArray, uint32 numLocations);
void peLocationArrayResizeLocations(peLocationArray LocationArray, uint32 numLocations);
void peLocationArrayFreeLocations(peLocationArray LocationArray);
void peCompactLocationArrayLocations(void);
utInlineC uint32 peLocationArrayGetLocationIndex_(peLocationArray LocationArray) {return peLocationArrays.LocationIndex_[peLocationArray2ValidIndex(LocationArray)];}
utInlineC void peLocationArraySetLocationIndex_(peLocationArray LocationArray, uint32 value) {peLocationArrays.LocationIndex_[peLocationArray2ValidIndex(LocationArray)] = value;}
utInlineC uint32 peLocationArrayGetNumLocation(peLocationArray LocationArray) {return peLocationArrays.NumLocation[peLocationArray2ValidIndex(LocationArray)];}
utInlineC void peLocationArraySetNumLocation(peLocationArray LocationArray, uint32 value) {peLocationArrays.NumLocation[peLocationArray2ValidIndex(LocationArray)] = value;}
#if defined(DD_DEBUG)
utInlineC uint32 peLocationArrayCheckLocationIndex(peLocationArray LocationArray, uint32 x) {utAssert(x < peLocationArrayGetNumLocation(LocationArray)); return x;}
#else
utInlineC uint32 peLocationArrayCheckLocationIndex(peLocationArray LocationArray, uint32 x) {return x;}
#endif
utInlineC peLocation peLocationArrayGetiLocation(peLocationArray LocationArray, uint32 x) {return peLocationArrays.Location[
    peLocationArrayGetLocationIndex_(LocationArray) + peLocationArrayCheckLocationIndex(LocationArray, x)];}
utInlineC peLocation *peLocationArrayGetLocation(peLocationArray LocationArray) {return peLocationArrays.Location + peLocationArrayGetLocationIndex_(LocationArray);}
#define peLocationArrayGetLocations peLocationArrayGetLocation
utInlineC void peLocationArraySetLocation(peLocationArray LocationArray, peLocation *valuePtr, uint32 numLocation) {
    peLocationArrayResizeLocations(LocationArray, numLocation);
    memcpy(peLocationArrayGetLocations(LocationArray), valuePtr, numLocation*sizeof(peLocation));}
utInlineC void peLocationArraySetiLocation(peLocationArray LocationArray, uint32 x, peLocation value) {
    peLocationArrays.Location[peLocationArrayGetLocationIndex_(LocationArray) + peLocationArrayCheckLocationIndex(LocationArray, (x))] = value;}
utInlineC uint32 peLocationArrayGetUsedLocation(peLocationArray LocationArray) {return peLocationArrays.UsedLocation[peLocationArray2ValidIndex(LocationArray)];}
utInlineC void peLocationArraySetUsedLocation(peLocationArray LocationArray, uint32 value) {peLocationArrays.UsedLocation[peLocationArray2ValidIndex(LocationArray)] = value;}
utInlineC peLocationArray peLocationArrayGetFreeList(peLocationArray LocationArray) {return peLocationArrays.FreeList[peLocationArray2ValidIndex(LocationArray)];}
utInlineC void peLocationArraySetFreeList(peLocationArray LocationArray, peLocationArray value) {peLocationArrays.FreeList[peLocationArray2ValidIndex(LocationArray)] = value;}
utInlineC void peLocationArraySetConstructorCallback(void(*func)(peLocationArray)) {peLocationArrayConstructorCallback = func;}
utInlineC peLocationArrayCallbackType peLocationArrayGetConstructorCallback(void) {return peLocationArrayConstructorCallback;}
utInlineC void peLocationArraySetDestructorCallback(void(*func)(peLocationArray)) {peLocationArrayDestructorCallback = func;}
utInlineC peLocationArrayCallbackType peLocationArrayGetDestructorCallback(void) {return peLocationArrayDestructorCallback;}
utInlineC peLocationArray peLocationArrayNextFree(peLocationArray LocationArray) {return ((peLocationArray *)(void *)(peLocationArrays.FreeList))[peLocationArray2ValidIndex(LocationArray)];}
utInlineC void peLocationArraySetNextFree(peLocationArray LocationArray, peLocationArray value) {
    ((peLocationArray *)(void *)(peLocationArrays.FreeList))[peLocationArray2ValidIndex(LocationArray)] = value;}
utInlineC void peLocationArrayFree(peLocationArray LocationArray) {
    peLocationArrayFreeLocations(LocationArray);
    peLocationArraySetNextFree(LocationArray, peRootData.firstFreeLocationArray);
    peSetFirstFreeLocationArray(LocationArray);}
void peLocationArrayDestroy(peLocationArray LocationArray);
utInlineC peLocationArray peLocationArrayAllocRaw(void) {
    peLocationArray LocationArray;
    if(peRootData.firstFreeLocationArray != peLocationArrayNull) {
        LocationArray = peRootData.firstFreeLocationArray;
        peSetFirstFreeLocationArray(peLocationArrayNextFree(LocationArray));
    } else {
        if(peRootData.usedLocationArray == peRootData.allocatedLocationArray) {
            peLocationArrayAllocMore();
        }
        LocationArray = peIndex2LocationArray(peRootData.usedLocationArray);
        peSetUsedLocationArray(peUsedLocationArray() + 1);
    }
    return LocationArray;}
utInlineC peLocationArray peLocationArrayAlloc(void) {
    peLocationArray LocationArray = peLocationArrayAllocRaw();
    peLocationArraySetLocationIndex_(LocationArray, 0);
    peLocationArraySetNumLocation(LocationArray, 0);
    peLocationArraySetNumLocation(LocationArray, 0);
    peLocationArraySetUsedLocation(LocationArray, 0);
    peLocationArraySetFreeList(LocationArray, peLocationArrayNull);
    if(peLocationArrayConstructorCallback != NULL) {
        peLocationArrayConstructorCallback(LocationArray);
    }
    return LocationArray;}

/*----------------------------------------------------------------------------------------
  Relationship macros between classes.
----------------------------------------------------------------------------------------*/
#define peForeachRootLocation(pVar, cVar) { \
    uint32 _xLocation; \
    for(_xLocation = 0; _xLocation < peRootGetUsedLocation(pVar); _xLocation++) { \
        cVar = peRootGetiLocation(pVar, _xLocation); \
        if(cVar != peLocationNull) {
#define peEndRootLocation }}}
#define peForeachRootGroup(pVar, cVar) \
    for(cVar = peRootGetFirstGroup(pVar); cVar != peGroupNull; \
        cVar = peGroupGetNextRootGroup(cVar))
#define peEndRootGroup
#define peSafeForeachRootGroup(pVar, cVar) { \
    peGroup _nextGroup; \
    for(cVar = peRootGetFirstGroup(pVar); cVar != peGroupNull; cVar = _nextGroup) { \
        _nextGroup = peGroupGetNextRootGroup(cVar);
#define peEndSafeRootGroup }}
void peRootInsertLocation(peRoot Root, uint32 x, peLocation _Location);
void peRootAppendLocation(peRoot Root, peLocation _Location);
void peRootRemoveLocation(peRoot Root, peLocation _Location);
void peRootInsertGroup(peRoot Root, peGroup _Group);
void peRootRemoveGroup(peRoot Root, peGroup _Group);
void peRootInsertAfterGroup(peRoot Root, peGroup prevGroup, peGroup _Group);
void peRootAppendGroup(peRoot Root, peGroup _Group);
#define peForeachLocationLocation(pVar, cVar) \
    for(cVar = peLocationGetFirstLocation(pVar); cVar != peLocationNull; \
        cVar = peLocationGetNextLocationLocation(cVar))
#define peEndLocationLocation
#define peSafeForeachLocationLocation(pVar, cVar) { \
    peLocation _nextLocation; \
    for(cVar = peLocationGetFirstLocation(pVar); cVar != peLocationNull; cVar = _nextLocation) { \
        _nextLocation = peLocationGetNextLocationLocation(cVar);
#define peEndSafeLocationLocation }}
utInlineC void peLocationInsertPebble(peLocation Location, pePebble _Pebble) {peLocationSetPebble(Location, _Pebble); pePebbleSetLocation(_Pebble, Location);}
utInlineC void peLocationRemovePebble(peLocation Location, pePebble _Pebble) {peLocationSetPebble(Location, pePebbleNull); pePebbleSetLocation(_Pebble, peLocationNull);}
void peLocationInsertLocation(peLocation Location, peLocation _Location);
void peLocationRemoveLocation(peLocation Location, peLocation _Location);
void peLocationInsertAfterLocation(peLocation Location, peLocation prevLocation, peLocation _Location);
void peLocationAppendLocation(peLocation Location, peLocation _Location);
#define peForeachGroupPebble(pVar, cVar) \
    for(cVar = peGroupGetFirstPebble(pVar); cVar != pePebbleNull; \
        cVar = pePebbleGetNextGroupPebble(cVar))
#define peEndGroupPebble
#define peSafeForeachGroupPebble(pVar, cVar) { \
    pePebble _nextPebble; \
    for(cVar = peGroupGetFirstPebble(pVar); cVar != pePebbleNull; cVar = _nextPebble) { \
        _nextPebble = pePebbleGetNextGroupPebble(cVar);
#define peEndSafeGroupPebble }}
void peGroupInsertPebble(peGroup Group, pePebble _Pebble);
void peGroupRemovePebble(peGroup Group, pePebble _Pebble);
void peGroupInsertAfterPebble(peGroup Group, pePebble prevPebble, pePebble _Pebble);
void peGroupAppendPebble(peGroup Group, pePebble _Pebble);
#define peForeachLocationArrayLocation(pVar, cVar) { \
    uint32 _xLocation; \
    for(_xLocation = 0; _xLocation < peLocationArrayGetUsedLocation(pVar); _xLocation++) { \
        cVar = peLocationArrayGetiLocation(pVar, _xLocation); \
        if(cVar != peLocationNull) {
#define peEndLocationArrayLocation }}}
void peLocationArrayInsertLocation(peLocationArray LocationArray, uint32 x, peLocation _Location);
void peLocationArrayAppendLocation(peLocationArray LocationArray, peLocation _Location);
void peDatabaseStart(void);
void peDatabaseStop(void);
utInlineC void peDatabaseSetSaved(bool value) {utModuleSetSaved(utModules + peModuleID, value);}
#if defined __cplusplus
}
#endif

#endif
