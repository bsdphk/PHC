PolyPassHash for C  
============

The C implementation for the [PolyPassHash password storage
scheme](https://github.com/JustinCappos/PolyPassHash). This repository provides
a C library to manage a polypasshash store.

A polypasshash store uses Shamir shares to obscure the password's hashes in 
order to make them unfeasible to crack. More details about this scheme can 
be seen [here](https://github.com/JustinCappos/PolyPassHash)


What's in here?
=======
Included, you will find an automake-autoconf-libtool project to build the
library, Instructions of how to build, and use.

A set of tests is also included. Tests are made for
[check](http://check.sourceforge.net). If you have check installed, running
make check will run all of the test suites.


Index
========
* [Building instructions](#building_instructions)
* [Compiling against polypasshash](#compiling)
* [Example Implementation](#example)
* [API Reference](#api)

<a name="building_instructions">
Building the library
=====================

## Requirements
In order to build this project, you will need to meet 
the following requirements:

- The open ssl development libraries (libssl-dev)

- The autoconf/automake/libtool binaries

- If you are running the tests, you need the check framework.

## How to build.
In order to build, we have to setup the project by running:
```Bash
  aclocal
  autoreconf
  automake --add-missing
  ./configure
  make
```

## Running the unit tests
After compiling, the unit tests can be run by using:
```Bash
  make check
```

## Installing the library
After compiling, the library is easily installed by running:
```Bash
  make install
```
We do, however, recommend running the tests before installing.

The installation script will copy the header files to /usr/local/include and
the shared .so into /usr/local/lib. 

<a name="compiling">
Compiling a program with libpolypasshash
========================================
After the installation has been done successfully, you can complile programs by
including the header inside your C implementation (#include <libpolypasshash.h>)

Compilation is done the following way:
```bash
  gcc -o polypasshash_example.out polypasshash_example.c -lcrypto -lpolypasshash
```


Running a program with libpolypasshash installed
===============================================
Since the shared object is not installed in the standard library path, in order
to run such programs you will need to export LD_LIBRARY_PATH before running, 
or copy the shared object into /usr/lib. The first alternative is suggested if
you are not familiar with these types of installations:

```Bash
  export $LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
  ./polypasshash_example.out
```

<a name="example">
An example implementation
=======

## The objective
In order to keep things simple, we are going to produce a store with some 
accounts, store it, reload it and unlock it. 

For the sake of simplicity, we are going to use only threshold accounts. The 
library supports thresholdless accounts, which are, in essence, user accounts
that cannot unlock the store (imagine normal users vs super users). 

We will also configure the context for two partial bytes. Partial bytes aid
us in providing a login capability even if the store is locked. The store
is usually locked upon reboot, since the shares are not stored anywhere in disk. 

```C

  // a context is the data structure that holds the information about the 
  // whole pph store
  pph_context *context;

  // Setting a theshold of two means that we are going to need two accounts 
  // to attempt unlocking. 
  uint8 threshold = 2;    
                          
  // partial bytes will be set to two, so users can login after any reboot
  // event.
  uint8 partial_bytes = 2;
                         


  // setup the context, this will generate us the shares, setup information 
  // needed to operate and initialize all of the data structures.
  context = pph_init_context(threshold, partial_bytes);
  
  
  // add some users, we send the context, a username, a password and a number
  // of shares to assign to the user. The a user can have many shares, and count
  // more towards the threshold. 
  pph_create_account(context, "Alice", strlen("Alice"),
                                       "I.love.bob", strlen("I.love.bob"), 1);
  pph_create_account(context, "Bob", strlen("Bob"),
                       "i.secretly.love.eve",strlen("i.secretly.love.eve"),1);
  
  // when creating a user with no shares, we get a *thresholdless* account. 
  // Thresholdless accounts have their hash encrypted and are unable to 
  // unlock a context
  pph_create_account(context,"Eve", strlen("Eve"),
                                   "i'm.all.ears", strlen("i'm.all.ears"), 0);
  
  // to check a login we must have an unlocked context, we send the credentials and 
  // receive an error in return
  if(pph_check_login(context, "Alice", strlen("Alice"), "I.love.bob",
         strlen("I.love.bob")) == PPH_ERROR_OK){
    printf("welcome alice\n");
  }else{
    printf("generic error message\n");
  }

  // We can, then store a context to work with it later, have in mind the 
  // context will be stored in a locked state and alice and bob will have 
  // to unlock it. 
  pph_store_context(context,"securepasswords");
  
  // We should destroy a context when we finish to free sensible data, such as
  // the share information. The pph_destroy_context function ensures that all
  // of the data structures associated with the context are properly freed. 
  pph_destroy_context(context);
  
  // time goes by and we want to start working again, with the same information
  // about alice, bob and eve...
  
  // We reload our context, we reload a context from disk using
  // pph_reload_context, providing a filename, remember that the obtained 
  // context is locked after loading from disk.
  context = pph_reload_context("securepasswords");
  
  // at this point we can still provide a login service, thanks to the partial 
  // bytes extension. But in order to create accounts and to provide full login
  // functionality, we should unlock the store.
  if(pph_check_login(context, "Alice",strlen("alice"), "i'm.trudy", 
                                          strlen("i'm.trudy")) == PPH_ERROR_OK){
    printf("welcome alice!\n"); // this won't happen
  }else{
    printf("go away trudy!\n");
  }

  // during the locked phase, we are unable to create accounts
  if(pph_create_account(context, "trudy", strlen("trudy"), "I'm.trudy", 
                            strlen("I'm.trudy"), 1) == PPH_CONTEXT_IS_LOCKED){
    printf("Sorry, we cannot create accounts at this time\n");
  }else{
    printf("!!! This shouldn't happen\n");
  }
  
  // In order to be able to create accounts, we must unlock the vault.
  // for this, we setup an array of username strings and an array of password 
  // strings.
  char **usernames = malloc(sizeof(*usernames)*2);
  usernames[0] = strdup("Alice");
  usernames[1] = strdup("Bob");
  
  char **passwords = malloc(sizeof(*passwords)*2);
  passwords[0] = strdup("I.love.bob");
  passwords[1] = strdup("i.secretly.love.eve");

  unsigned int *username_lengths = malloc(sizeof(*username_lengths)*2);
  username_lengths[0] = strlen("Alice");
  username_lengths[1] = strlen("bob");
  
  
  // if the information provided was correct, the pph_unlock_password_data
  // returns PPH_ERROR_OK, unlocks the vault and recovers the secrets.
  pph_unlock_password_data(context, 2, usernames, username_lengths, passwords);

  // now the data us unlocked. We can create accounts now.
  pph_create_account(context, "carl", strlen("carl"), "verysafe", 
                                                        strlen("verysafe"),0);
  
  // we can now check accounts using the full feature also (non-partial bytes)
  if(pph_check_login(context, "carl", strlen("carl"), "verysafe",
                                          strlen("verysafe")) == PPH_ERROR_OK){
    printf("welcome back carl\n"); 
  }else{
    printf("you are not carl");
  }
  
  
  // we should now store the context and free the data before leaving
  pph_store_context(context,"securepasswords");
  pph_destroy_context(context);

```
<a name="api">
API reference
=========
The API is a simple set of functions to aid you in the creation and management of a PolyPassHash scheme. 

* [data structures](#data_structures)
* [functions](#functions)
  * [context management](#context_management)
    * [pph\_init\_context](#pph_init_context)
    * [pph\_destroy\_context](#pph_destroy_context)
    * [pph\_store\_context](#pph_store_context)
    * [pph\_reload\_context](#pph_reload_context)
    * [pph\_unlock\_password\_data](#pph_unlock_password_data)
  * [user\_management](#user_management_functions)
    * [pph\_create\_account](#pph_create_account)
    * [pph\_check\_login](#pph_check_login)
  * [other functions](#other_functions)
    * [ PHS ](#PHS)

<a name="data_structures"/>
## Data structures
### pph context
The pph context is oriented to facilitate the bookkeeping of changes in the context, it holds the user data, the secret (if available), a reference to the shamir secret sharing data structure, etc. This is a quick overview of the data structure:
```C
  typedef struct _pph_context{
  gfshare_ctx *share_context;    // this is a pointer to the libgfshare engine
  uint8 threshold;               // the threshold set to the libgfshare engine
  uint8 available_shares;        // this is the number of available shares
  uint8 is_unlocked;             // this is a boolean flag indicating whether 
                                 //  the secret is known.
  uint8 *AES_key;                // a randomly generated AES key of SHARE_LENGTH
  uint8 *secret;                 // secret data, generated at initialization
  uint8 partial_bytes;           // partial bytes, if 0, partial verification is
                                 //   disabled
  pph_account_node* account_data;// we will hold a reference to the account
                                 //  data in here
  uint8 next_entry;              // this assigns shares in a round-robin 
                                 //  fashion
}pph_context;
```
### pph\_account and the pph\_entry
These are structures that contain information about user accounts and their
specific shares. As a user of this library, you won't need to address them. 


<a name="functions"/>
## Functions
Functions in the libpolypasshash library are divided in user management or context management. User management functions carry the role of user adding and login check. Context management functions are oriented to the maintenance and operation of the whole polypasshash scheme. 

====


<a name="context_managemet"/>
### Context management functions.

====


<a name="pph_init_context"/>
#### pph\_init\_context
Initializes a polypasshash context structure with everything needed in order to work. This is a one-time only initialization, pph_store_context and pph_reload_context will provide a persistent context after initialization.
##### parameters:
  
* Threshold : the minimum number of shares (or username accounts) to provide in order for it to unlock

* patial_bytes : how many bytes are non-obscured by either the AES key or the shamir secret in order to provide partial verification.

##### returns 
An initialized pph_context

====



<a name="pph_destroy_context"/>
#### pph\_destroy\_context


Safely destroy all of the references in an initialized pph_context. 

###### parameters

* pph_context: the context to destroy.

###### returns
An error code indicating whether the operation was successful or not. 
 
==== 
   
   
 
 
<a name="pph_store_context"/>
#### pph\_store\_context
Persist the non-sensitive information about a context to disk. Have in mind 
that certain parameters (such as the secret) are not written to disk. In other
words, the context written to disk is stored in a locked state.

###### Parameters

* context : the context to persist

* filename : the name of the file to persist

###### returns
An error code indicating whether the operation was successful or what was the 
reason for failure.

====




<a name="pph_reload_context"/>
#### pph\_reload\_context
After successfull context-storage, you can reload the context into memory by 
using this function. A reloaded context is locked until the pph_unlock_password_data
function is called. A locked context may not operate for creating accounts, and can
only verify logins if the partial bytes argument provided was non-zero.

###### Parameters

* filename : the filename of the context to reload


###### returns
A locked, but initialized, pph_context. 

====



<a name="pph_unlock_password_data"/>
#### pph\_unlock\_password\_data.
Provided a sufficient accounts (above the threshold), attempt to unlock the 
context data structure. 

###### parameters

* context : the context to attempt unlocking

* username_count : the number of accounts provided

* usernames : an array of usernames to attempt unlocking

* username_lengths: an array containing the length of each specific username

* passwords : an array of passwords correspoding to each username in the same index

###### returns
An error indicating if the attempt was successful or not.

====




<a name="user_management_functions"/>
### User Management Functions

====



<a name="pph\_create\_account"/>
#### pph\_create\_account
Given some credentials and an unlocked context, store the user data inside a 
context. 

###### parameters

* context : the context in which the user will be added

* username : the username field, if it already exists, the system will throw an error

* username_length : the length of the username field.

* password : the password for that secific user.

* password_length : the length of the password field

###### returns
An error indicating whether the account could be added, or the cause of failure. 
Too long usernames and passwords will return an error, as well as an already 
existing account. 

====




<a name="pph_check_login"/>
#### pph\_check\_login
Provided a username and password pair, check if such pair exists within th context.

###### parameters

* context : the context that stores the account information.

* username : the username to look for.

* username_length : the length of the username provided

* password : the password attempt for such username

* password_length : the length of the password field provided. 

###### returns 
An error code indicating if the login attempt was successful.

====



<a name="other_functions"/>
### Other functions

====

<a name="PHS"/>
#### PHS
Hash an input string with the given arguments.

This function is a mere demonstration of the resulting hashes inside a polypasshash store.
The motivation behind this function is to showcase the safety of the polyhashed passwords. This function is aimed for the Password Hashing Competition.

###### parameters

  * void * out: The output hash
  
  * size_t outlen: the length of the produced string
  
  * void * in:  The input password
  
  * size_t inlen: the length of the input password

  * void * salt: A salt input
  
  * size_t saltlen: The length of the input salt
  
  * int tcost: a time cost, in this case, this parameter modifies the threshold of the produced context directly.

  * int mcost: a memory/ other cost parameter

###### returns 
An error code indicating if the hash procedure was successful. If the function is successful, the resulting hash will be placed in the out buffer.

====
