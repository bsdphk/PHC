/*----------------------------------------------------------------------------------------
  Database pe
----------------------------------------------------------------------------------------*/

#include "pedatabase.h"

struct peRootType_ peRootData;
uint8 peModuleID;
struct peRootFields peRoots;
struct pePebbleFields pePebbles;
struct peLocationFields peLocations;
struct peGroupFields peGroups;
struct peLocationArrayFields peLocationArrays;

/*----------------------------------------------------------------------------------------
  Constructor/Destructor hooks.
----------------------------------------------------------------------------------------*/
peRootCallbackType peRootConstructorCallback;
peRootCallbackType peRootDestructorCallback;
pePebbleCallbackType pePebbleConstructorCallback;
pePebbleCallbackType pePebbleDestructorCallback;
peLocationCallbackType peLocationConstructorCallback;
peLocationCallbackType peLocationDestructorCallback;
peGroupCallbackType peGroupConstructorCallback;
peGroupCallbackType peGroupDestructorCallback;
peLocationArrayCallbackType peLocationArrayConstructorCallback;
peLocationArrayCallbackType peLocationArrayDestructorCallback;

/*----------------------------------------------------------------------------------------
  Destroy Root including everything in it. Remove from parents.
----------------------------------------------------------------------------------------*/
void peRootDestroy(
    peRoot Root)
{
    peLocation Location_;
    uint32 xLocation;
    peGroup Group_;

    if(peRootDestructorCallback != NULL) {
        peRootDestructorCallback(Root);
    }
    for(xLocation = 0; xLocation < peRootGetUsedLocation(Root); xLocation++) {
        Location_ = peRootGetiLocation(Root, xLocation);
        if(Location_ != peLocationNull) {
            peLocationDestroy(Location_);
        }
    }
    peSafeForeachRootGroup(Root, Group_) {
        peGroupDestroy(Group_);
    } peEndSafeRootGroup;
    peRootFree(Root);
}

/*----------------------------------------------------------------------------------------
  Default constructor wrapper for the database manager.
----------------------------------------------------------------------------------------*/
static uint64 allocRoot(void)
{
    peRoot Root = peRootAlloc();

    return peRoot2Index(Root);
}

/*----------------------------------------------------------------------------------------
  Destructor wrapper for the database manager.
----------------------------------------------------------------------------------------*/
static void destroyRoot(
    uint64 objectIndex)
{
    peRootDestroy(peIndex2Root((uint32)objectIndex));
}

/*----------------------------------------------------------------------------------------
  Allocate the field arrays of Root.
----------------------------------------------------------------------------------------*/
static void allocRoots(void)
{
    peSetAllocatedRoot(2);
    peSetUsedRoot(1);
    peSetFirstFreeRoot(peRootNull);
    peRoots.LocationIndex_ = utNewAInitFirst(uint32, (peAllocatedRoot()));
    peRoots.NumLocation = utNewAInitFirst(uint32, (peAllocatedRoot()));
    peSetUsedRootLocation(0);
    peSetAllocatedRootLocation(2);
    peSetFreeRootLocation(0);
    peRoots.Location = utNewAInitFirst(peLocation, peAllocatedRootLocation());
    peRoots.UsedLocation = utNewAInitFirst(uint32, (peAllocatedRoot()));
    peRoots.FirstGroup = utNewAInitFirst(peGroup, (peAllocatedRoot()));
    peRoots.LastGroup = utNewAInitFirst(peGroup, (peAllocatedRoot()));
}

/*----------------------------------------------------------------------------------------
  Realloc the arrays of properties for class Root.
----------------------------------------------------------------------------------------*/
static void reallocRoots(
    uint32 newSize)
{
    utResizeArray(peRoots.LocationIndex_, (newSize));
    utResizeArray(peRoots.NumLocation, (newSize));
    utResizeArray(peRoots.UsedLocation, (newSize));
    utResizeArray(peRoots.FirstGroup, (newSize));
    utResizeArray(peRoots.LastGroup, (newSize));
    peSetAllocatedRoot(newSize);
}

/*----------------------------------------------------------------------------------------
  Allocate more Roots.
----------------------------------------------------------------------------------------*/
void peRootAllocMore(void)
{
    reallocRoots((uint32)(peAllocatedRoot() + (peAllocatedRoot() >> 1)));
}

/*----------------------------------------------------------------------------------------
  Compact the Root.Location heap to free memory.
----------------------------------------------------------------------------------------*/
void peCompactRootLocations(void)
{
    uint32 elementSize = sizeof(peLocation);
    uint32 usedHeaderSize = (sizeof(peRoot) + elementSize - 1)/elementSize;
    uint32 freeHeaderSize = (sizeof(peRoot) + sizeof(uint32) + elementSize - 1)/elementSize;
    peLocation *toPtr = peRoots.Location;
    peLocation *fromPtr = toPtr;
    peRoot Root;
    uint32 size;

    while(fromPtr < peRoots.Location + peUsedRootLocation()) {
        Root = *(peRoot *)(void *)fromPtr;
        if(Root != peRootNull) {
            /* Need to move it to toPtr */
            size = utMax(peRootGetNumLocation(Root) + usedHeaderSize, freeHeaderSize);
            memmove((void *)toPtr, (void *)fromPtr, size*elementSize);
            peRootSetLocationIndex_(Root, toPtr - peRoots.Location + usedHeaderSize);
            toPtr += size;
        } else {
            /* Just skip it */
            size = utMax(*(uint32 *)(void *)(((peRoot *)(void *)fromPtr) + 1), freeHeaderSize);
        }
        fromPtr += size;
    }
    peSetUsedRootLocation(toPtr - peRoots.Location);
    peSetFreeRootLocation(0);
}

/*----------------------------------------------------------------------------------------
  Allocate more memory for the Root.Location heap.
----------------------------------------------------------------------------------------*/
static void allocMoreRootLocations(
    uint32 spaceNeeded)
{
    uint32 freeSpace = peAllocatedRootLocation() - peUsedRootLocation();
    uint32 elementSize = sizeof(peLocation);
    uint32 usedHeaderSize = (sizeof(peRoot) + elementSize - 1)/elementSize;
    uint32 freeHeaderSize = (sizeof(peRoot) + sizeof(uint32) + elementSize - 1)/elementSize;
    peLocation *ptr = peRoots.Location;
    peRoot Root;
    uint32 size;

    while(ptr < peRoots.Location + peUsedRootLocation()) {
        Root = *(peRoot*)(void*)ptr;
        if(Root != peRootNull) {
            peValidRoot(Root);
            size = utMax(peRootGetNumLocation(Root) + usedHeaderSize, freeHeaderSize);
        } else {
            size = utMax(*(uint32 *)(void *)(((peRoot *)(void *)ptr) + 1), freeHeaderSize);
        }
        ptr += size;
    }
    if((peFreeRootLocation() << 2) > peUsedRootLocation()) {
        peCompactRootLocations();
        freeSpace = peAllocatedRootLocation() - peUsedRootLocation();
    }
    if(freeSpace < spaceNeeded) {
        peSetAllocatedRootLocation(peAllocatedRootLocation() + spaceNeeded - freeSpace +
            (peAllocatedRootLocation() >> 1));
        utResizeArray(peRoots.Location, peAllocatedRootLocation());
    }
}

/*----------------------------------------------------------------------------------------
  Allocate memory for a new Root.Location array.
----------------------------------------------------------------------------------------*/
void peRootAllocLocations(
    peRoot Root,
    uint32 numLocations)
{
    uint32 freeSpace = peAllocatedRootLocation() - peUsedRootLocation();
    uint32 elementSize = sizeof(peLocation);
    uint32 usedHeaderSize = (sizeof(peRoot) + elementSize - 1)/elementSize;
    uint32 freeHeaderSize = (sizeof(peRoot) + sizeof(uint32) + elementSize - 1)/elementSize;
    uint32 spaceNeeded = utMax(numLocations + usedHeaderSize, freeHeaderSize);

#if defined(DD_DEBUG)
    utAssert(peRootGetNumLocation(Root) == 0);
#endif
    if(numLocations == 0) {
        return;
    }
    if(freeSpace < spaceNeeded) {
        allocMoreRootLocations(spaceNeeded);
    }
    peRootSetLocationIndex_(Root, peUsedRootLocation() + usedHeaderSize);
    peRootSetNumLocation(Root, numLocations);
    *(peRoot *)(void *)(peRoots.Location + peUsedRootLocation()) = Root;
    {
        uint32 xValue;
        for(xValue = (uint32)(peRootGetLocationIndex_(Root)); xValue < peRootGetLocationIndex_(Root) + numLocations; xValue++) {
            peRoots.Location[xValue] = peLocationNull;
        }
    }
    peSetUsedRootLocation(peUsedRootLocation() + spaceNeeded);
}

/*----------------------------------------------------------------------------------------
  Wrapper around peRootGetLocations for the database manager.
----------------------------------------------------------------------------------------*/
static void *getRootLocations(
    uint64 objectNumber,
    uint32 *numValues)
{
    peRoot Root = peIndex2Root((uint32)objectNumber);

    *numValues = peRootGetNumLocation(Root);
    return peRootGetLocations(Root);
}

/*----------------------------------------------------------------------------------------
  Wrapper around peRootAllocLocations for the database manager.
----------------------------------------------------------------------------------------*/
static void *allocRootLocations(
    uint64 objectNumber,
    uint32 numValues)
{
    peRoot Root = peIndex2Root((uint32)objectNumber);

    peRootSetLocationIndex_(Root, 0);
    peRootSetNumLocation(Root, 0);
    if(numValues == 0) {
        return NULL;
    }
    peRootAllocLocations(Root, numValues);
    return peRootGetLocations(Root);
}

/*----------------------------------------------------------------------------------------
  Free memory used by the Root.Location array.
----------------------------------------------------------------------------------------*/
void peRootFreeLocations(
    peRoot Root)
{
    uint32 elementSize = sizeof(peLocation);
    uint32 usedHeaderSize = (sizeof(peRoot) + elementSize - 1)/elementSize;
    uint32 freeHeaderSize = (sizeof(peRoot) + sizeof(uint32) + elementSize - 1)/elementSize;
    uint32 size = utMax(peRootGetNumLocation(Root) + usedHeaderSize, freeHeaderSize);
    peLocation *dataPtr = peRootGetLocations(Root) - usedHeaderSize;

    if(peRootGetNumLocation(Root) == 0) {
        return;
    }
    *(peRoot *)(void *)(dataPtr) = peRootNull;
    *(uint32 *)(void *)(((peRoot *)(void *)dataPtr) + 1) = size;
    peRootSetNumLocation(Root, 0);
    peSetFreeRootLocation(peFreeRootLocation() + size);
}

/*----------------------------------------------------------------------------------------
  Resize the Root.Location array.
----------------------------------------------------------------------------------------*/
void peRootResizeLocations(
    peRoot Root,
    uint32 numLocations)
{
    uint32 freeSpace;
    uint32 elementSize = sizeof(peLocation);
    uint32 usedHeaderSize = (sizeof(peRoot) + elementSize - 1)/elementSize;
    uint32 freeHeaderSize = (sizeof(peRoot) + sizeof(uint32) + elementSize - 1)/elementSize;
    uint32 newSize = utMax(numLocations + usedHeaderSize, freeHeaderSize);
    uint32 oldSize = utMax(peRootGetNumLocation(Root) + usedHeaderSize, freeHeaderSize);
    peLocation *dataPtr;

    if(numLocations == 0) {
        if(peRootGetNumLocation(Root) != 0) {
            peRootFreeLocations(Root);
        }
        return;
    }
    if(peRootGetNumLocation(Root) == 0) {
        peRootAllocLocations(Root, numLocations);
        return;
    }
    freeSpace = peAllocatedRootLocation() - peUsedRootLocation();
    if(freeSpace < newSize) {
        allocMoreRootLocations(newSize);
    }
    dataPtr = peRootGetLocations(Root) - usedHeaderSize;
    memcpy((void *)(peRoots.Location + peUsedRootLocation()), dataPtr,
        elementSize*utMin(oldSize, newSize));
    if(newSize > oldSize) {
        {
            uint32 xValue;
            for(xValue = (uint32)(peUsedRootLocation() + oldSize); xValue < peUsedRootLocation() + oldSize + newSize - oldSize; xValue++) {
                peRoots.Location[xValue] = peLocationNull;
            }
        }
    }
    *(peRoot *)(void *)dataPtr = peRootNull;
    *(uint32 *)(void *)(((peRoot *)(void *)dataPtr) + 1) = oldSize;
    peSetFreeRootLocation(peFreeRootLocation() + oldSize);
    peRootSetLocationIndex_(Root, peUsedRootLocation() + usedHeaderSize);
    peRootSetNumLocation(Root, numLocations);
    peSetUsedRootLocation(peUsedRootLocation() + newSize);
}

/*----------------------------------------------------------------------------------------
  Copy the properties of Root.
----------------------------------------------------------------------------------------*/
void peRootCopyProps(
    peRoot oldRoot,
    peRoot newRoot)
{
}

/*----------------------------------------------------------------------------------------
  Add the indexed Location to the Root.
----------------------------------------------------------------------------------------*/
void peRootInsertLocation(
    peRoot Root,
    uint32 x,
    peLocation _Location)
{
#if defined(DD_DEBUG)
    if(Root == peRootNull) {
        utExit("Non existent Root");
    }
    if(peLocationGetRoot(_Location) != peRootNull) {
        utExit("Attempting to add Location to Root twice");
    }
#endif
    peRootSetiLocation(Root, x, _Location);
    peRootSetUsedLocation(Root, utMax(peRootGetUsedLocation(Root), x + 1));
    peLocationSetRootIndex(_Location, x);
    peLocationSetRoot(_Location, Root);
}

/*----------------------------------------------------------------------------------------
  Add the Location to the end of the RootLocation array.
----------------------------------------------------------------------------------------*/
void peRootAppendLocation(
    peRoot Root,
    peLocation _Location)
{
    uint32 usedLocation = peRootGetUsedLocation(Root);

#if defined(DD_DEBUG)
    if(Root == peRootNull) {
        utExit("Non existent Root");
    }
#endif
    if(usedLocation >= peRootGetNumLocation(Root)) {
        peRootResizeLocations(Root, usedLocation + (usedLocation << 1) + 1);
    }
    peRootSetiLocation(Root, usedLocation, _Location);
    peRootSetUsedLocation(Root, usedLocation + 1);
    peLocationSetRootIndex(_Location, usedLocation);
    peLocationSetRoot(_Location, Root);
}

/*----------------------------------------------------------------------------------------
  Remove the Location from the Root.
----------------------------------------------------------------------------------------*/
void peRootRemoveLocation(
    peRoot Root,
    peLocation _Location)
{
#if defined(DD_DEBUG)
    if(_Location == peLocationNull) {
        utExit("Non-existent Location");
    }
    if(peLocationGetRoot(_Location) != peRootNull && peLocationGetRoot(_Location) != Root) {
        utExit("Delete Location from non-owning Root");
    }
#endif
    peRootSetiLocation(Root, peLocationGetRootIndex(_Location), peLocationNull);
    peLocationSetRootIndex(_Location, UINT32_MAX);
    peLocationSetRoot(_Location, peRootNull);
}

/*----------------------------------------------------------------------------------------
  Add the Group to the head of the list on the Root.
----------------------------------------------------------------------------------------*/
void peRootInsertGroup(
    peRoot Root,
    peGroup _Group)
{
#if defined(DD_DEBUG)
    if(Root == peRootNull) {
        utExit("Non-existent Root");
    }
    if(_Group == peGroupNull) {
        utExit("Non-existent Group");
    }
    if(peGroupGetRoot(_Group) != peRootNull) {
        utExit("Attempting to add Group to Root twice");
    }
#endif
    peGroupSetNextRootGroup(_Group, peRootGetFirstGroup(Root));
    if(peRootGetFirstGroup(Root) != peGroupNull) {
        peGroupSetPrevRootGroup(peRootGetFirstGroup(Root), _Group);
    }
    peRootSetFirstGroup(Root, _Group);
    peGroupSetPrevRootGroup(_Group, peGroupNull);
    if(peRootGetLastGroup(Root) == peGroupNull) {
        peRootSetLastGroup(Root, _Group);
    }
    peGroupSetRoot(_Group, Root);
}

/*----------------------------------------------------------------------------------------
  Add the Group to the end of the list on the Root.
----------------------------------------------------------------------------------------*/
void peRootAppendGroup(
    peRoot Root,
    peGroup _Group)
{
#if defined(DD_DEBUG)
    if(Root == peRootNull) {
        utExit("Non-existent Root");
    }
    if(_Group == peGroupNull) {
        utExit("Non-existent Group");
    }
    if(peGroupGetRoot(_Group) != peRootNull) {
        utExit("Attempting to add Group to Root twice");
    }
#endif
    peGroupSetPrevRootGroup(_Group, peRootGetLastGroup(Root));
    if(peRootGetLastGroup(Root) != peGroupNull) {
        peGroupSetNextRootGroup(peRootGetLastGroup(Root), _Group);
    }
    peRootSetLastGroup(Root, _Group);
    peGroupSetNextRootGroup(_Group, peGroupNull);
    if(peRootGetFirstGroup(Root) == peGroupNull) {
        peRootSetFirstGroup(Root, _Group);
    }
    peGroupSetRoot(_Group, Root);
}

/*----------------------------------------------------------------------------------------
  Insert the Group to the Root after the previous Group.
----------------------------------------------------------------------------------------*/
void peRootInsertAfterGroup(
    peRoot Root,
    peGroup prevGroup,
    peGroup _Group)
{
    peGroup nextGroup = peGroupGetNextRootGroup(prevGroup);

#if defined(DD_DEBUG)
    if(Root == peRootNull) {
        utExit("Non-existent Root");
    }
    if(_Group == peGroupNull) {
        utExit("Non-existent Group");
    }
    if(peGroupGetRoot(_Group) != peRootNull) {
        utExit("Attempting to add Group to Root twice");
    }
#endif
    peGroupSetNextRootGroup(_Group, nextGroup);
    peGroupSetNextRootGroup(prevGroup, _Group);
    peGroupSetPrevRootGroup(_Group, prevGroup);
    if(nextGroup != peGroupNull) {
        peGroupSetPrevRootGroup(nextGroup, _Group);
    }
    if(peRootGetLastGroup(Root) == prevGroup) {
        peRootSetLastGroup(Root, _Group);
    }
    peGroupSetRoot(_Group, Root);
}

/*----------------------------------------------------------------------------------------
 Remove the Group from the Root.
----------------------------------------------------------------------------------------*/
void peRootRemoveGroup(
    peRoot Root,
    peGroup _Group)
{
    peGroup pGroup, nGroup;

#if defined(DD_DEBUG)
    if(_Group == peGroupNull) {
        utExit("Non-existent Group");
    }
    if(peGroupGetRoot(_Group) != peRootNull && peGroupGetRoot(_Group) != Root) {
        utExit("Delete Group from non-owning Root");
    }
#endif
    nGroup = peGroupGetNextRootGroup(_Group);
    pGroup = peGroupGetPrevRootGroup(_Group);
    if(pGroup != peGroupNull) {
        peGroupSetNextRootGroup(pGroup, nGroup);
    } else if(peRootGetFirstGroup(Root) == _Group) {
        peRootSetFirstGroup(Root, nGroup);
    }
    if(nGroup != peGroupNull) {
        peGroupSetPrevRootGroup(nGroup, pGroup);
    } else if(peRootGetLastGroup(Root) == _Group) {
        peRootSetLastGroup(Root, pGroup);
    }
    peGroupSetNextRootGroup(_Group, peGroupNull);
    peGroupSetPrevRootGroup(_Group, peGroupNull);
    peGroupSetRoot(_Group, peRootNull);
}

#if defined(DD_DEBUG)
/*----------------------------------------------------------------------------------------
  Write out all the fields of an object.
----------------------------------------------------------------------------------------*/
void peShowRoot(
    peRoot Root)
{
    utDatabaseShowObject("pe", "Root", peRoot2Index(Root));
}
#endif

/*----------------------------------------------------------------------------------------
  Destroy Pebble including everything in it. Remove from parents.
----------------------------------------------------------------------------------------*/
void pePebbleDestroy(
    pePebble Pebble)
{
    peLocation owningLocation = pePebbleGetLocation(Pebble);
    peGroup owningGroup = pePebbleGetGroup(Pebble);

    if(pePebbleDestructorCallback != NULL) {
        pePebbleDestructorCallback(Pebble);
    }
    if(owningLocation != peLocationNull) {
        peLocationSetPebble(owningLocation, pePebbleNull);
#if defined(DD_DEBUG)
    } else {
        utExit("Pebble without owning Location");
#endif
    }
    if(owningGroup != peGroupNull) {
        peGroupRemovePebble(owningGroup, Pebble);
    }
    pePebbleFree(Pebble);
}

/*----------------------------------------------------------------------------------------
  Default constructor wrapper for the database manager.
----------------------------------------------------------------------------------------*/
static uint64 allocPebble(void)
{
    pePebble Pebble = pePebbleAlloc();

    return pePebble2Index(Pebble);
}

/*----------------------------------------------------------------------------------------
  Destructor wrapper for the database manager.
----------------------------------------------------------------------------------------*/
static void destroyPebble(
    uint64 objectIndex)
{
    pePebbleDestroy(peIndex2Pebble((uint32)objectIndex));
}

/*----------------------------------------------------------------------------------------
  Allocate the field arrays of Pebble.
----------------------------------------------------------------------------------------*/
static void allocPebbles(void)
{
    peSetAllocatedPebble(2);
    peSetUsedPebble(1);
    peSetFirstFreePebble(pePebbleNull);
    pePebbles.Location = utNewAInitFirst(peLocation, (peAllocatedPebble()));
    pePebbles.Group = utNewAInitFirst(peGroup, (peAllocatedPebble()));
    pePebbles.NextGroupPebble = utNewAInitFirst(pePebble, (peAllocatedPebble()));
    pePebbles.PrevGroupPebble = utNewAInitFirst(pePebble, (peAllocatedPebble()));
}

/*----------------------------------------------------------------------------------------
  Realloc the arrays of properties for class Pebble.
----------------------------------------------------------------------------------------*/
static void reallocPebbles(
    uint32 newSize)
{
    utResizeArray(pePebbles.Location, (newSize));
    utResizeArray(pePebbles.Group, (newSize));
    utResizeArray(pePebbles.NextGroupPebble, (newSize));
    utResizeArray(pePebbles.PrevGroupPebble, (newSize));
    peSetAllocatedPebble(newSize);
}

/*----------------------------------------------------------------------------------------
  Allocate more Pebbles.
----------------------------------------------------------------------------------------*/
void pePebbleAllocMore(void)
{
    reallocPebbles((uint32)(peAllocatedPebble() + (peAllocatedPebble() >> 1)));
}

/*----------------------------------------------------------------------------------------
  Copy the properties of Pebble.
----------------------------------------------------------------------------------------*/
void pePebbleCopyProps(
    pePebble oldPebble,
    pePebble newPebble)
{
}

#if defined(DD_DEBUG)
/*----------------------------------------------------------------------------------------
  Write out all the fields of an object.
----------------------------------------------------------------------------------------*/
void peShowPebble(
    pePebble Pebble)
{
    utDatabaseShowObject("pe", "Pebble", pePebble2Index(Pebble));
}
#endif

/*----------------------------------------------------------------------------------------
  Destroy Location including everything in it. Remove from parents.
----------------------------------------------------------------------------------------*/
void peLocationDestroy(
    peLocation Location)
{
    pePebble Pebble_;
    peLocation Location_;
    peRoot owningRoot = peLocationGetRoot(Location);
    peLocation owningLocation = peLocationGetLocation(Location);

    if(peLocationDestructorCallback != NULL) {
        peLocationDestructorCallback(Location);
    }
    Pebble_ = peLocationGetPebble(Location);
    if(Pebble_ != pePebbleNull) {
        pePebbleDestroy(Pebble_);
    }
    peSafeForeachLocationLocation(Location, Location_) {
        peLocationSetLocation(Location_, peLocationNull);
    } peEndSafeLocationLocation;
    if(owningRoot != peRootNull) {
        peRootRemoveLocation(owningRoot, Location);
#if defined(DD_DEBUG)
    } else {
        utExit("Location without owning Root");
#endif
    }
    if(owningLocation != peLocationNull) {
        peLocationRemoveLocation(owningLocation, Location);
    }
    peLocationFree(Location);
}

/*----------------------------------------------------------------------------------------
  Default constructor wrapper for the database manager.
----------------------------------------------------------------------------------------*/
static uint64 allocLocation(void)
{
    peLocation Location = peLocationAlloc();

    return peLocation2Index(Location);
}

/*----------------------------------------------------------------------------------------
  Destructor wrapper for the database manager.
----------------------------------------------------------------------------------------*/
static void destroyLocation(
    uint64 objectIndex)
{
    peLocationDestroy(peIndex2Location((uint32)objectIndex));
}

/*----------------------------------------------------------------------------------------
  Allocate the field arrays of Location.
----------------------------------------------------------------------------------------*/
static void allocLocations(void)
{
    peSetAllocatedLocation(2);
    peSetUsedLocation(1);
    peSetFirstFreeLocation(peLocationNull);
    peLocations.NumPointers = utNewAInitFirst(uint32, (peAllocatedLocation()));
    peLocations.Recomputations = utNewAInitFirst(uint32, (peAllocatedLocation()));
    peLocations.UseCount = utNewAInitFirst(uint8, (peAllocatedLocation()));
    peLocations.Fixed = utNewAInitFirst(uint8, (peAllocatedLocation()));
    peLocations.Visited = utNewAInitFirst(uint8, (peAllocatedLocation()));
    peLocations.Root = utNewAInitFirst(peRoot, (peAllocatedLocation()));
    peLocations.RootIndex = utNewAInitFirst(uint32, (peAllocatedLocation()));
    peLocations.Pebble = utNewAInitFirst(pePebble, (peAllocatedLocation()));
    peLocations.Location = utNewAInitFirst(peLocation, (peAllocatedLocation()));
    peLocations.FirstLocation = utNewAInitFirst(peLocation, (peAllocatedLocation()));
    peLocations.NextLocationLocation = utNewAInitFirst(peLocation, (peAllocatedLocation()));
    peLocations.LastLocation = utNewAInitFirst(peLocation, (peAllocatedLocation()));
    peLocations.PrevLocationLocation = utNewAInitFirst(peLocation, (peAllocatedLocation()));
}

/*----------------------------------------------------------------------------------------
  Realloc the arrays of properties for class Location.
----------------------------------------------------------------------------------------*/
static void reallocLocations(
    uint32 newSize)
{
    utResizeArray(peLocations.NumPointers, (newSize));
    utResizeArray(peLocations.Recomputations, (newSize));
    utResizeArray(peLocations.UseCount, (newSize));
    utResizeArray(peLocations.Fixed, (newSize));
    utResizeArray(peLocations.Visited, (newSize));
    utResizeArray(peLocations.Root, (newSize));
    utResizeArray(peLocations.RootIndex, (newSize));
    utResizeArray(peLocations.Pebble, (newSize));
    utResizeArray(peLocations.Location, (newSize));
    utResizeArray(peLocations.FirstLocation, (newSize));
    utResizeArray(peLocations.NextLocationLocation, (newSize));
    utResizeArray(peLocations.LastLocation, (newSize));
    utResizeArray(peLocations.PrevLocationLocation, (newSize));
    peSetAllocatedLocation(newSize);
}

/*----------------------------------------------------------------------------------------
  Allocate more Locations.
----------------------------------------------------------------------------------------*/
void peLocationAllocMore(void)
{
    reallocLocations((uint32)(peAllocatedLocation() + (peAllocatedLocation() >> 1)));
}

/*----------------------------------------------------------------------------------------
  Copy the properties of Location.
----------------------------------------------------------------------------------------*/
void peLocationCopyProps(
    peLocation oldLocation,
    peLocation newLocation)
{
    peLocationSetNumPointers(newLocation, peLocationGetNumPointers(oldLocation));
    peLocationSetRecomputations(newLocation, peLocationGetRecomputations(oldLocation));
    peLocationSetUseCount(newLocation, peLocationGetUseCount(oldLocation));
    peLocationSetFixed(newLocation, peLocationFixed(oldLocation));
    peLocationSetVisited(newLocation, peLocationVisited(oldLocation));
}

/*----------------------------------------------------------------------------------------
  Add the Location to the head of the list on the Location.
----------------------------------------------------------------------------------------*/
void peLocationInsertLocation(
    peLocation Location,
    peLocation _Location)
{
#if defined(DD_DEBUG)
    if(Location == peLocationNull) {
        utExit("Non-existent Location");
    }
    if(_Location == peLocationNull) {
        utExit("Non-existent Location");
    }
    if(peLocationGetLocation(_Location) != peLocationNull) {
        utExit("Attempting to add Location to Location twice");
    }
#endif
    peLocationSetNextLocationLocation(_Location, peLocationGetFirstLocation(Location));
    if(peLocationGetFirstLocation(Location) != peLocationNull) {
        peLocationSetPrevLocationLocation(peLocationGetFirstLocation(Location), _Location);
    }
    peLocationSetFirstLocation(Location, _Location);
    peLocationSetPrevLocationLocation(_Location, peLocationNull);
    if(peLocationGetLastLocation(Location) == peLocationNull) {
        peLocationSetLastLocation(Location, _Location);
    }
    peLocationSetLocation(_Location, Location);
}

/*----------------------------------------------------------------------------------------
  Add the Location to the end of the list on the Location.
----------------------------------------------------------------------------------------*/
void peLocationAppendLocation(
    peLocation Location,
    peLocation _Location)
{
#if defined(DD_DEBUG)
    if(Location == peLocationNull) {
        utExit("Non-existent Location");
    }
    if(_Location == peLocationNull) {
        utExit("Non-existent Location");
    }
    if(peLocationGetLocation(_Location) != peLocationNull) {
        utExit("Attempting to add Location to Location twice");
    }
#endif
    peLocationSetPrevLocationLocation(_Location, peLocationGetLastLocation(Location));
    if(peLocationGetLastLocation(Location) != peLocationNull) {
        peLocationSetNextLocationLocation(peLocationGetLastLocation(Location), _Location);
    }
    peLocationSetLastLocation(Location, _Location);
    peLocationSetNextLocationLocation(_Location, peLocationNull);
    if(peLocationGetFirstLocation(Location) == peLocationNull) {
        peLocationSetFirstLocation(Location, _Location);
    }
    peLocationSetLocation(_Location, Location);
}

/*----------------------------------------------------------------------------------------
  Insert the Location to the Location after the previous Location.
----------------------------------------------------------------------------------------*/
void peLocationInsertAfterLocation(
    peLocation Location,
    peLocation prevLocation,
    peLocation _Location)
{
    peLocation nextLocation = peLocationGetNextLocationLocation(prevLocation);

#if defined(DD_DEBUG)
    if(Location == peLocationNull) {
        utExit("Non-existent Location");
    }
    if(_Location == peLocationNull) {
        utExit("Non-existent Location");
    }
    if(peLocationGetLocation(_Location) != peLocationNull) {
        utExit("Attempting to add Location to Location twice");
    }
#endif
    peLocationSetNextLocationLocation(_Location, nextLocation);
    peLocationSetNextLocationLocation(prevLocation, _Location);
    peLocationSetPrevLocationLocation(_Location, prevLocation);
    if(nextLocation != peLocationNull) {
        peLocationSetPrevLocationLocation(nextLocation, _Location);
    }
    if(peLocationGetLastLocation(Location) == prevLocation) {
        peLocationSetLastLocation(Location, _Location);
    }
    peLocationSetLocation(_Location, Location);
}

/*----------------------------------------------------------------------------------------
 Remove the Location from the Location.
----------------------------------------------------------------------------------------*/
void peLocationRemoveLocation(
    peLocation Location,
    peLocation _Location)
{
    peLocation pLocation, nLocation;

#if defined(DD_DEBUG)
    if(_Location == peLocationNull) {
        utExit("Non-existent Location");
    }
    if(peLocationGetLocation(_Location) != peLocationNull && peLocationGetLocation(_Location) != Location) {
        utExit("Delete Location from non-owning Location");
    }
#endif
    nLocation = peLocationGetNextLocationLocation(_Location);
    pLocation = peLocationGetPrevLocationLocation(_Location);
    if(pLocation != peLocationNull) {
        peLocationSetNextLocationLocation(pLocation, nLocation);
    } else if(peLocationGetFirstLocation(Location) == _Location) {
        peLocationSetFirstLocation(Location, nLocation);
    }
    if(nLocation != peLocationNull) {
        peLocationSetPrevLocationLocation(nLocation, pLocation);
    } else if(peLocationGetLastLocation(Location) == _Location) {
        peLocationSetLastLocation(Location, pLocation);
    }
    peLocationSetNextLocationLocation(_Location, peLocationNull);
    peLocationSetPrevLocationLocation(_Location, peLocationNull);
    peLocationSetLocation(_Location, peLocationNull);
}

#if defined(DD_DEBUG)
/*----------------------------------------------------------------------------------------
  Write out all the fields of an object.
----------------------------------------------------------------------------------------*/
void peShowLocation(
    peLocation Location)
{
    utDatabaseShowObject("pe", "Location", peLocation2Index(Location));
}
#endif

/*----------------------------------------------------------------------------------------
  Destroy Group including everything in it. Remove from parents.
----------------------------------------------------------------------------------------*/
void peGroupDestroy(
    peGroup Group)
{
    pePebble Pebble_;
    peRoot owningRoot = peGroupGetRoot(Group);

    if(peGroupDestructorCallback != NULL) {
        peGroupDestructorCallback(Group);
    }
    peSafeForeachGroupPebble(Group, Pebble_) {
        pePebbleSetGroup(Pebble_, peGroupNull);
    } peEndSafeGroupPebble;
    if(owningRoot != peRootNull) {
        peRootRemoveGroup(owningRoot, Group);
#if defined(DD_DEBUG)
    } else {
        utExit("Group without owning Root");
#endif
    }
    peGroupFree(Group);
}

/*----------------------------------------------------------------------------------------
  Default constructor wrapper for the database manager.
----------------------------------------------------------------------------------------*/
static uint64 allocGroup(void)
{
    peGroup Group = peGroupAlloc();

    return peGroup2Index(Group);
}

/*----------------------------------------------------------------------------------------
  Destructor wrapper for the database manager.
----------------------------------------------------------------------------------------*/
static void destroyGroup(
    uint64 objectIndex)
{
    peGroupDestroy(peIndex2Group((uint32)objectIndex));
}

/*----------------------------------------------------------------------------------------
  Allocate the field arrays of Group.
----------------------------------------------------------------------------------------*/
static void allocGroups(void)
{
    peSetAllocatedGroup(2);
    peSetUsedGroup(1);
    peSetFirstFreeGroup(peGroupNull);
    peGroups.AvailablePebbles = utNewAInitFirst(uint32, (peAllocatedGroup()));
    peGroups.Root = utNewAInitFirst(peRoot, (peAllocatedGroup()));
    peGroups.NextRootGroup = utNewAInitFirst(peGroup, (peAllocatedGroup()));
    peGroups.PrevRootGroup = utNewAInitFirst(peGroup, (peAllocatedGroup()));
    peGroups.FirstPebble = utNewAInitFirst(pePebble, (peAllocatedGroup()));
    peGroups.LastPebble = utNewAInitFirst(pePebble, (peAllocatedGroup()));
}

/*----------------------------------------------------------------------------------------
  Realloc the arrays of properties for class Group.
----------------------------------------------------------------------------------------*/
static void reallocGroups(
    uint32 newSize)
{
    utResizeArray(peGroups.AvailablePebbles, (newSize));
    utResizeArray(peGroups.Root, (newSize));
    utResizeArray(peGroups.NextRootGroup, (newSize));
    utResizeArray(peGroups.PrevRootGroup, (newSize));
    utResizeArray(peGroups.FirstPebble, (newSize));
    utResizeArray(peGroups.LastPebble, (newSize));
    peSetAllocatedGroup(newSize);
}

/*----------------------------------------------------------------------------------------
  Allocate more Groups.
----------------------------------------------------------------------------------------*/
void peGroupAllocMore(void)
{
    reallocGroups((uint32)(peAllocatedGroup() + (peAllocatedGroup() >> 1)));
}

/*----------------------------------------------------------------------------------------
  Copy the properties of Group.
----------------------------------------------------------------------------------------*/
void peGroupCopyProps(
    peGroup oldGroup,
    peGroup newGroup)
{
    peGroupSetAvailablePebbles(newGroup, peGroupGetAvailablePebbles(oldGroup));
}

/*----------------------------------------------------------------------------------------
  Add the Pebble to the head of the list on the Group.
----------------------------------------------------------------------------------------*/
void peGroupInsertPebble(
    peGroup Group,
    pePebble _Pebble)
{
#if defined(DD_DEBUG)
    if(Group == peGroupNull) {
        utExit("Non-existent Group");
    }
    if(_Pebble == pePebbleNull) {
        utExit("Non-existent Pebble");
    }
    if(pePebbleGetGroup(_Pebble) != peGroupNull) {
        utExit("Attempting to add Pebble to Group twice");
    }
#endif
    pePebbleSetNextGroupPebble(_Pebble, peGroupGetFirstPebble(Group));
    if(peGroupGetFirstPebble(Group) != pePebbleNull) {
        pePebbleSetPrevGroupPebble(peGroupGetFirstPebble(Group), _Pebble);
    }
    peGroupSetFirstPebble(Group, _Pebble);
    pePebbleSetPrevGroupPebble(_Pebble, pePebbleNull);
    if(peGroupGetLastPebble(Group) == pePebbleNull) {
        peGroupSetLastPebble(Group, _Pebble);
    }
    pePebbleSetGroup(_Pebble, Group);
}

/*----------------------------------------------------------------------------------------
  Add the Pebble to the end of the list on the Group.
----------------------------------------------------------------------------------------*/
void peGroupAppendPebble(
    peGroup Group,
    pePebble _Pebble)
{
#if defined(DD_DEBUG)
    if(Group == peGroupNull) {
        utExit("Non-existent Group");
    }
    if(_Pebble == pePebbleNull) {
        utExit("Non-existent Pebble");
    }
    if(pePebbleGetGroup(_Pebble) != peGroupNull) {
        utExit("Attempting to add Pebble to Group twice");
    }
#endif
    pePebbleSetPrevGroupPebble(_Pebble, peGroupGetLastPebble(Group));
    if(peGroupGetLastPebble(Group) != pePebbleNull) {
        pePebbleSetNextGroupPebble(peGroupGetLastPebble(Group), _Pebble);
    }
    peGroupSetLastPebble(Group, _Pebble);
    pePebbleSetNextGroupPebble(_Pebble, pePebbleNull);
    if(peGroupGetFirstPebble(Group) == pePebbleNull) {
        peGroupSetFirstPebble(Group, _Pebble);
    }
    pePebbleSetGroup(_Pebble, Group);
}

/*----------------------------------------------------------------------------------------
  Insert the Pebble to the Group after the previous Pebble.
----------------------------------------------------------------------------------------*/
void peGroupInsertAfterPebble(
    peGroup Group,
    pePebble prevPebble,
    pePebble _Pebble)
{
    pePebble nextPebble = pePebbleGetNextGroupPebble(prevPebble);

#if defined(DD_DEBUG)
    if(Group == peGroupNull) {
        utExit("Non-existent Group");
    }
    if(_Pebble == pePebbleNull) {
        utExit("Non-existent Pebble");
    }
    if(pePebbleGetGroup(_Pebble) != peGroupNull) {
        utExit("Attempting to add Pebble to Group twice");
    }
#endif
    pePebbleSetNextGroupPebble(_Pebble, nextPebble);
    pePebbleSetNextGroupPebble(prevPebble, _Pebble);
    pePebbleSetPrevGroupPebble(_Pebble, prevPebble);
    if(nextPebble != pePebbleNull) {
        pePebbleSetPrevGroupPebble(nextPebble, _Pebble);
    }
    if(peGroupGetLastPebble(Group) == prevPebble) {
        peGroupSetLastPebble(Group, _Pebble);
    }
    pePebbleSetGroup(_Pebble, Group);
}

/*----------------------------------------------------------------------------------------
 Remove the Pebble from the Group.
----------------------------------------------------------------------------------------*/
void peGroupRemovePebble(
    peGroup Group,
    pePebble _Pebble)
{
    pePebble pPebble, nPebble;

#if defined(DD_DEBUG)
    if(_Pebble == pePebbleNull) {
        utExit("Non-existent Pebble");
    }
    if(pePebbleGetGroup(_Pebble) != peGroupNull && pePebbleGetGroup(_Pebble) != Group) {
        utExit("Delete Pebble from non-owning Group");
    }
#endif
    nPebble = pePebbleGetNextGroupPebble(_Pebble);
    pPebble = pePebbleGetPrevGroupPebble(_Pebble);
    if(pPebble != pePebbleNull) {
        pePebbleSetNextGroupPebble(pPebble, nPebble);
    } else if(peGroupGetFirstPebble(Group) == _Pebble) {
        peGroupSetFirstPebble(Group, nPebble);
    }
    if(nPebble != pePebbleNull) {
        pePebbleSetPrevGroupPebble(nPebble, pPebble);
    } else if(peGroupGetLastPebble(Group) == _Pebble) {
        peGroupSetLastPebble(Group, pPebble);
    }
    pePebbleSetNextGroupPebble(_Pebble, pePebbleNull);
    pePebbleSetPrevGroupPebble(_Pebble, pePebbleNull);
    pePebbleSetGroup(_Pebble, peGroupNull);
}

#if defined(DD_DEBUG)
/*----------------------------------------------------------------------------------------
  Write out all the fields of an object.
----------------------------------------------------------------------------------------*/
void peShowGroup(
    peGroup Group)
{
    utDatabaseShowObject("pe", "Group", peGroup2Index(Group));
}
#endif

/*----------------------------------------------------------------------------------------
  Destroy LocationArray including everything in it. Remove from parents.
----------------------------------------------------------------------------------------*/
void peLocationArrayDestroy(
    peLocationArray LocationArray)
{
    if(peLocationArrayDestructorCallback != NULL) {
        peLocationArrayDestructorCallback(LocationArray);
    }
    peLocationArrayFree(LocationArray);
}

/*----------------------------------------------------------------------------------------
  Default constructor wrapper for the database manager.
----------------------------------------------------------------------------------------*/
static uint64 allocLocationArray(void)
{
    peLocationArray LocationArray = peLocationArrayAlloc();

    return peLocationArray2Index(LocationArray);
}

/*----------------------------------------------------------------------------------------
  Destructor wrapper for the database manager.
----------------------------------------------------------------------------------------*/
static void destroyLocationArray(
    uint64 objectIndex)
{
    peLocationArrayDestroy(peIndex2LocationArray((uint32)objectIndex));
}

/*----------------------------------------------------------------------------------------
  Allocate the field arrays of LocationArray.
----------------------------------------------------------------------------------------*/
static void allocLocationArrays(void)
{
    peSetAllocatedLocationArray(2);
    peSetUsedLocationArray(1);
    peSetFirstFreeLocationArray(peLocationArrayNull);
    peLocationArrays.LocationIndex_ = utNewAInitFirst(uint32, (peAllocatedLocationArray()));
    peLocationArrays.NumLocation = utNewAInitFirst(uint32, (peAllocatedLocationArray()));
    peSetUsedLocationArrayLocation(0);
    peSetAllocatedLocationArrayLocation(2);
    peSetFreeLocationArrayLocation(0);
    peLocationArrays.Location = utNewAInitFirst(peLocation, peAllocatedLocationArrayLocation());
    peLocationArrays.UsedLocation = utNewAInitFirst(uint32, (peAllocatedLocationArray()));
    peLocationArrays.FreeList = utNewAInitFirst(peLocationArray, (peAllocatedLocationArray()));
}

/*----------------------------------------------------------------------------------------
  Realloc the arrays of properties for class LocationArray.
----------------------------------------------------------------------------------------*/
static void reallocLocationArrays(
    uint32 newSize)
{
    utResizeArray(peLocationArrays.LocationIndex_, (newSize));
    utResizeArray(peLocationArrays.NumLocation, (newSize));
    utResizeArray(peLocationArrays.UsedLocation, (newSize));
    utResizeArray(peLocationArrays.FreeList, (newSize));
    peSetAllocatedLocationArray(newSize);
}

/*----------------------------------------------------------------------------------------
  Allocate more LocationArrays.
----------------------------------------------------------------------------------------*/
void peLocationArrayAllocMore(void)
{
    reallocLocationArrays((uint32)(peAllocatedLocationArray() + (peAllocatedLocationArray() >> 1)));
}

/*----------------------------------------------------------------------------------------
  Compact the LocationArray.Location heap to free memory.
----------------------------------------------------------------------------------------*/
void peCompactLocationArrayLocations(void)
{
    uint32 elementSize = sizeof(peLocation);
    uint32 usedHeaderSize = (sizeof(peLocationArray) + elementSize - 1)/elementSize;
    uint32 freeHeaderSize = (sizeof(peLocationArray) + sizeof(uint32) + elementSize - 1)/elementSize;
    peLocation *toPtr = peLocationArrays.Location;
    peLocation *fromPtr = toPtr;
    peLocationArray LocationArray;
    uint32 size;

    while(fromPtr < peLocationArrays.Location + peUsedLocationArrayLocation()) {
        LocationArray = *(peLocationArray *)(void *)fromPtr;
        if(LocationArray != peLocationArrayNull) {
            /* Need to move it to toPtr */
            size = utMax(peLocationArrayGetNumLocation(LocationArray) + usedHeaderSize, freeHeaderSize);
            memmove((void *)toPtr, (void *)fromPtr, size*elementSize);
            peLocationArraySetLocationIndex_(LocationArray, toPtr - peLocationArrays.Location + usedHeaderSize);
            toPtr += size;
        } else {
            /* Just skip it */
            size = utMax(*(uint32 *)(void *)(((peLocationArray *)(void *)fromPtr) + 1), freeHeaderSize);
        }
        fromPtr += size;
    }
    peSetUsedLocationArrayLocation(toPtr - peLocationArrays.Location);
    peSetFreeLocationArrayLocation(0);
}

/*----------------------------------------------------------------------------------------
  Allocate more memory for the LocationArray.Location heap.
----------------------------------------------------------------------------------------*/
static void allocMoreLocationArrayLocations(
    uint32 spaceNeeded)
{
    uint32 freeSpace = peAllocatedLocationArrayLocation() - peUsedLocationArrayLocation();
    uint32 elementSize = sizeof(peLocation);
    uint32 usedHeaderSize = (sizeof(peLocationArray) + elementSize - 1)/elementSize;
    uint32 freeHeaderSize = (sizeof(peLocationArray) + sizeof(uint32) + elementSize - 1)/elementSize;
    peLocation *ptr = peLocationArrays.Location;
    peLocationArray LocationArray;
    uint32 size;

    while(ptr < peLocationArrays.Location + peUsedLocationArrayLocation()) {
        LocationArray = *(peLocationArray*)(void*)ptr;
        if(LocationArray != peLocationArrayNull) {
            peValidLocationArray(LocationArray);
            size = utMax(peLocationArrayGetNumLocation(LocationArray) + usedHeaderSize, freeHeaderSize);
        } else {
            size = utMax(*(uint32 *)(void *)(((peLocationArray *)(void *)ptr) + 1), freeHeaderSize);
        }
        ptr += size;
    }
    if((peFreeLocationArrayLocation() << 2) > peUsedLocationArrayLocation()) {
        peCompactLocationArrayLocations();
        freeSpace = peAllocatedLocationArrayLocation() - peUsedLocationArrayLocation();
    }
    if(freeSpace < spaceNeeded) {
        peSetAllocatedLocationArrayLocation(peAllocatedLocationArrayLocation() + spaceNeeded - freeSpace +
            (peAllocatedLocationArrayLocation() >> 1));
        utResizeArray(peLocationArrays.Location, peAllocatedLocationArrayLocation());
    }
}

/*----------------------------------------------------------------------------------------
  Allocate memory for a new LocationArray.Location array.
----------------------------------------------------------------------------------------*/
void peLocationArrayAllocLocations(
    peLocationArray LocationArray,
    uint32 numLocations)
{
    uint32 freeSpace = peAllocatedLocationArrayLocation() - peUsedLocationArrayLocation();
    uint32 elementSize = sizeof(peLocation);
    uint32 usedHeaderSize = (sizeof(peLocationArray) + elementSize - 1)/elementSize;
    uint32 freeHeaderSize = (sizeof(peLocationArray) + sizeof(uint32) + elementSize - 1)/elementSize;
    uint32 spaceNeeded = utMax(numLocations + usedHeaderSize, freeHeaderSize);

#if defined(DD_DEBUG)
    utAssert(peLocationArrayGetNumLocation(LocationArray) == 0);
#endif
    if(numLocations == 0) {
        return;
    }
    if(freeSpace < spaceNeeded) {
        allocMoreLocationArrayLocations(spaceNeeded);
    }
    peLocationArraySetLocationIndex_(LocationArray, peUsedLocationArrayLocation() + usedHeaderSize);
    peLocationArraySetNumLocation(LocationArray, numLocations);
    *(peLocationArray *)(void *)(peLocationArrays.Location + peUsedLocationArrayLocation()) = LocationArray;
    {
        uint32 xValue;
        for(xValue = (uint32)(peLocationArrayGetLocationIndex_(LocationArray)); xValue < peLocationArrayGetLocationIndex_(LocationArray) + numLocations; xValue++) {
            peLocationArrays.Location[xValue] = peLocationNull;
        }
    }
    peSetUsedLocationArrayLocation(peUsedLocationArrayLocation() + spaceNeeded);
}

/*----------------------------------------------------------------------------------------
  Wrapper around peLocationArrayGetLocations for the database manager.
----------------------------------------------------------------------------------------*/
static void *getLocationArrayLocations(
    uint64 objectNumber,
    uint32 *numValues)
{
    peLocationArray LocationArray = peIndex2LocationArray((uint32)objectNumber);

    *numValues = peLocationArrayGetNumLocation(LocationArray);
    return peLocationArrayGetLocations(LocationArray);
}

/*----------------------------------------------------------------------------------------
  Wrapper around peLocationArrayAllocLocations for the database manager.
----------------------------------------------------------------------------------------*/
static void *allocLocationArrayLocations(
    uint64 objectNumber,
    uint32 numValues)
{
    peLocationArray LocationArray = peIndex2LocationArray((uint32)objectNumber);

    peLocationArraySetLocationIndex_(LocationArray, 0);
    peLocationArraySetNumLocation(LocationArray, 0);
    if(numValues == 0) {
        return NULL;
    }
    peLocationArrayAllocLocations(LocationArray, numValues);
    return peLocationArrayGetLocations(LocationArray);
}

/*----------------------------------------------------------------------------------------
  Free memory used by the LocationArray.Location array.
----------------------------------------------------------------------------------------*/
void peLocationArrayFreeLocations(
    peLocationArray LocationArray)
{
    uint32 elementSize = sizeof(peLocation);
    uint32 usedHeaderSize = (sizeof(peLocationArray) + elementSize - 1)/elementSize;
    uint32 freeHeaderSize = (sizeof(peLocationArray) + sizeof(uint32) + elementSize - 1)/elementSize;
    uint32 size = utMax(peLocationArrayGetNumLocation(LocationArray) + usedHeaderSize, freeHeaderSize);
    peLocation *dataPtr = peLocationArrayGetLocations(LocationArray) - usedHeaderSize;

    if(peLocationArrayGetNumLocation(LocationArray) == 0) {
        return;
    }
    *(peLocationArray *)(void *)(dataPtr) = peLocationArrayNull;
    *(uint32 *)(void *)(((peLocationArray *)(void *)dataPtr) + 1) = size;
    peLocationArraySetNumLocation(LocationArray, 0);
    peSetFreeLocationArrayLocation(peFreeLocationArrayLocation() + size);
}

/*----------------------------------------------------------------------------------------
  Resize the LocationArray.Location array.
----------------------------------------------------------------------------------------*/
void peLocationArrayResizeLocations(
    peLocationArray LocationArray,
    uint32 numLocations)
{
    uint32 freeSpace;
    uint32 elementSize = sizeof(peLocation);
    uint32 usedHeaderSize = (sizeof(peLocationArray) + elementSize - 1)/elementSize;
    uint32 freeHeaderSize = (sizeof(peLocationArray) + sizeof(uint32) + elementSize - 1)/elementSize;
    uint32 newSize = utMax(numLocations + usedHeaderSize, freeHeaderSize);
    uint32 oldSize = utMax(peLocationArrayGetNumLocation(LocationArray) + usedHeaderSize, freeHeaderSize);
    peLocation *dataPtr;

    if(numLocations == 0) {
        if(peLocationArrayGetNumLocation(LocationArray) != 0) {
            peLocationArrayFreeLocations(LocationArray);
        }
        return;
    }
    if(peLocationArrayGetNumLocation(LocationArray) == 0) {
        peLocationArrayAllocLocations(LocationArray, numLocations);
        return;
    }
    freeSpace = peAllocatedLocationArrayLocation() - peUsedLocationArrayLocation();
    if(freeSpace < newSize) {
        allocMoreLocationArrayLocations(newSize);
    }
    dataPtr = peLocationArrayGetLocations(LocationArray) - usedHeaderSize;
    memcpy((void *)(peLocationArrays.Location + peUsedLocationArrayLocation()), dataPtr,
        elementSize*utMin(oldSize, newSize));
    if(newSize > oldSize) {
        {
            uint32 xValue;
            for(xValue = (uint32)(peUsedLocationArrayLocation() + oldSize); xValue < peUsedLocationArrayLocation() + oldSize + newSize - oldSize; xValue++) {
                peLocationArrays.Location[xValue] = peLocationNull;
            }
        }
    }
    *(peLocationArray *)(void *)dataPtr = peLocationArrayNull;
    *(uint32 *)(void *)(((peLocationArray *)(void *)dataPtr) + 1) = oldSize;
    peSetFreeLocationArrayLocation(peFreeLocationArrayLocation() + oldSize);
    peLocationArraySetLocationIndex_(LocationArray, peUsedLocationArrayLocation() + usedHeaderSize);
    peLocationArraySetNumLocation(LocationArray, numLocations);
    peSetUsedLocationArrayLocation(peUsedLocationArrayLocation() + newSize);
}

/*----------------------------------------------------------------------------------------
  Copy the properties of LocationArray.
----------------------------------------------------------------------------------------*/
void peLocationArrayCopyProps(
    peLocationArray oldLocationArray,
    peLocationArray newLocationArray)
{
}

/*----------------------------------------------------------------------------------------
  Add the indexed Location to the LocationArray.
----------------------------------------------------------------------------------------*/
void peLocationArrayInsertLocation(
    peLocationArray LocationArray,
    uint32 x,
    peLocation _Location)
{
#if defined(DD_DEBUG)
    if(LocationArray == peLocationArrayNull) {
        utExit("Non existent LocationArray");
    }
#endif
    peLocationArraySetiLocation(LocationArray, x, _Location);
    peLocationArraySetUsedLocation(LocationArray, utMax(peLocationArrayGetUsedLocation(LocationArray), x + 1));
}

/*----------------------------------------------------------------------------------------
  Add the Location to the end of the LocationArrayLocation array.
----------------------------------------------------------------------------------------*/
void peLocationArrayAppendLocation(
    peLocationArray LocationArray,
    peLocation _Location)
{
    uint32 usedLocation = peLocationArrayGetUsedLocation(LocationArray);

#if defined(DD_DEBUG)
    if(LocationArray == peLocationArrayNull) {
        utExit("Non existent LocationArray");
    }
#endif
    if(usedLocation >= peLocationArrayGetNumLocation(LocationArray)) {
        peLocationArrayResizeLocations(LocationArray, usedLocation + (usedLocation << 1) + 1);
    }
    peLocationArraySetiLocation(LocationArray, usedLocation, _Location);
    peLocationArraySetUsedLocation(LocationArray, usedLocation + 1);
}

#if defined(DD_DEBUG)
/*----------------------------------------------------------------------------------------
  Write out all the fields of an object.
----------------------------------------------------------------------------------------*/
void peShowLocationArray(
    peLocationArray LocationArray)
{
    utDatabaseShowObject("pe", "LocationArray", peLocationArray2Index(LocationArray));
}
#endif

/*----------------------------------------------------------------------------------------
  Free memory used by the pe database.
----------------------------------------------------------------------------------------*/
void peDatabaseStop(void)
{
    utFree(peRoots.LocationIndex_);
    utFree(peRoots.NumLocation);
    utFree(peRoots.Location);
    utFree(peRoots.UsedLocation);
    utFree(peRoots.FirstGroup);
    utFree(peRoots.LastGroup);
    utFree(pePebbles.Location);
    utFree(pePebbles.Group);
    utFree(pePebbles.NextGroupPebble);
    utFree(pePebbles.PrevGroupPebble);
    utFree(peLocations.NumPointers);
    utFree(peLocations.Recomputations);
    utFree(peLocations.UseCount);
    utFree(peLocations.Fixed);
    utFree(peLocations.Visited);
    utFree(peLocations.Root);
    utFree(peLocations.RootIndex);
    utFree(peLocations.Pebble);
    utFree(peLocations.Location);
    utFree(peLocations.FirstLocation);
    utFree(peLocations.NextLocationLocation);
    utFree(peLocations.LastLocation);
    utFree(peLocations.PrevLocationLocation);
    utFree(peGroups.AvailablePebbles);
    utFree(peGroups.Root);
    utFree(peGroups.NextRootGroup);
    utFree(peGroups.PrevRootGroup);
    utFree(peGroups.FirstPebble);
    utFree(peGroups.LastPebble);
    utFree(peLocationArrays.LocationIndex_);
    utFree(peLocationArrays.NumLocation);
    utFree(peLocationArrays.Location);
    utFree(peLocationArrays.UsedLocation);
    utFree(peLocationArrays.FreeList);
    utUnregisterModule(peModuleID);
}

/*----------------------------------------------------------------------------------------
  Allocate memory used by the pe database.
----------------------------------------------------------------------------------------*/
void peDatabaseStart(void)
{
    if(!utInitialized()) {
        utStart();
    }
    peRootData.hash = 0x2e1d9910;
    peModuleID = utRegisterModule("pe", false, peHash(), 5, 34, 0, sizeof(struct peRootType_),
        &peRootData, peDatabaseStart, peDatabaseStop);
    utRegisterClass("Root", 6, &peRootData.usedRoot, &peRootData.allocatedRoot,
        &peRootData.firstFreeRoot, 4, 4, allocRoot, destroyRoot);
    utRegisterField("LocationIndex_", &peRoots.LocationIndex_, sizeof(uint32), UT_UINT, NULL);
    utSetFieldHidden();
    utRegisterField("NumLocation", &peRoots.NumLocation, sizeof(uint32), UT_UINT, NULL);
    utSetFieldHidden();
    utRegisterField("Location", &peRoots.Location, sizeof(peLocation), UT_POINTER, "Location");
    utRegisterArray(&peRootData.usedRootLocation, &peRootData.allocatedRootLocation,
        getRootLocations, allocRootLocations, peCompactRootLocations);
    utRegisterField("UsedLocation", &peRoots.UsedLocation, sizeof(uint32), UT_UINT, NULL);
    utRegisterField("FirstGroup", &peRoots.FirstGroup, sizeof(peGroup), UT_POINTER, "Group");
    utRegisterField("LastGroup", &peRoots.LastGroup, sizeof(peGroup), UT_POINTER, "Group");
    utRegisterClass("Pebble", 4, &peRootData.usedPebble, &peRootData.allocatedPebble,
        &peRootData.firstFreePebble, 6, 4, allocPebble, destroyPebble);
    utRegisterField("Location", &pePebbles.Location, sizeof(peLocation), UT_POINTER, "Location");
    utRegisterField("Group", &pePebbles.Group, sizeof(peGroup), UT_POINTER, "Group");
    utRegisterField("NextGroupPebble", &pePebbles.NextGroupPebble, sizeof(pePebble), UT_POINTER, "Pebble");
    utRegisterField("PrevGroupPebble", &pePebbles.PrevGroupPebble, sizeof(pePebble), UT_POINTER, "Pebble");
    utRegisterClass("Location", 13, &peRootData.usedLocation, &peRootData.allocatedLocation,
        &peRootData.firstFreeLocation, 15, 4, allocLocation, destroyLocation);
    utRegisterField("NumPointers", &peLocations.NumPointers, sizeof(uint32), UT_UINT, NULL);
    utRegisterField("Recomputations", &peLocations.Recomputations, sizeof(uint32), UT_UINT, NULL);
    utRegisterField("UseCount", &peLocations.UseCount, sizeof(uint8), UT_UINT, NULL);
    utRegisterField("Fixed", &peLocations.Fixed, sizeof(uint8), UT_BOOL, NULL);
    utRegisterField("Visited", &peLocations.Visited, sizeof(uint8), UT_BOOL, NULL);
    utRegisterField("Root", &peLocations.Root, sizeof(peRoot), UT_POINTER, "Root");
    utRegisterField("RootIndex", &peLocations.RootIndex, sizeof(uint32), UT_UINT, NULL);
    utRegisterField("Pebble", &peLocations.Pebble, sizeof(pePebble), UT_POINTER, "Pebble");
    utRegisterField("Location", &peLocations.Location, sizeof(peLocation), UT_POINTER, "Location");
    utRegisterField("FirstLocation", &peLocations.FirstLocation, sizeof(peLocation), UT_POINTER, "Location");
    utRegisterField("NextLocationLocation", &peLocations.NextLocationLocation, sizeof(peLocation), UT_POINTER, "Location");
    utRegisterField("LastLocation", &peLocations.LastLocation, sizeof(peLocation), UT_POINTER, "Location");
    utRegisterField("PrevLocationLocation", &peLocations.PrevLocationLocation, sizeof(peLocation), UT_POINTER, "Location");
    utRegisterClass("Group", 6, &peRootData.usedGroup, &peRootData.allocatedGroup,
        &peRootData.firstFreeGroup, 24, 4, allocGroup, destroyGroup);
    utRegisterField("AvailablePebbles", &peGroups.AvailablePebbles, sizeof(uint32), UT_UINT, NULL);
    utRegisterField("Root", &peGroups.Root, sizeof(peRoot), UT_POINTER, "Root");
    utRegisterField("NextRootGroup", &peGroups.NextRootGroup, sizeof(peGroup), UT_POINTER, "Group");
    utRegisterField("PrevRootGroup", &peGroups.PrevRootGroup, sizeof(peGroup), UT_POINTER, "Group");
    utRegisterField("FirstPebble", &peGroups.FirstPebble, sizeof(pePebble), UT_POINTER, "Pebble");
    utRegisterField("LastPebble", &peGroups.LastPebble, sizeof(pePebble), UT_POINTER, "Pebble");
    utRegisterClass("LocationArray", 5, &peRootData.usedLocationArray, &peRootData.allocatedLocationArray,
        &peRootData.firstFreeLocationArray, 33, 4, allocLocationArray, destroyLocationArray);
    utRegisterField("LocationIndex_", &peLocationArrays.LocationIndex_, sizeof(uint32), UT_UINT, NULL);
    utSetFieldHidden();
    utRegisterField("NumLocation", &peLocationArrays.NumLocation, sizeof(uint32), UT_UINT, NULL);
    utSetFieldHidden();
    utRegisterField("Location", &peLocationArrays.Location, sizeof(peLocation), UT_POINTER, "Location");
    utRegisterArray(&peRootData.usedLocationArrayLocation, &peRootData.allocatedLocationArrayLocation,
        getLocationArrayLocations, allocLocationArrayLocations, peCompactLocationArrayLocations);
    utRegisterField("UsedLocation", &peLocationArrays.UsedLocation, sizeof(uint32), UT_UINT, NULL);
    utRegisterField("FreeList", &peLocationArrays.FreeList, sizeof(peLocationArray), UT_POINTER, "LocationArray");
    utSetFieldHidden();
    allocRoots();
    allocPebbles();
    allocLocations();
    allocGroups();
    allocLocationArrays();
}

