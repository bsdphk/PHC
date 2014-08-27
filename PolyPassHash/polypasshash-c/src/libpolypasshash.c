/*
 * This file is Copyright Santiago Torres Arias <torresariass@gmail.com> 2014
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */

//#include "config.h"
#include "libgfshare.h"
#include "libpolypasshash.h"




/*******************************************************************
* NAME :            pph_init_context
*
* DESCRIPTION :     Initialize a poly pass hash structure with everything
*                   we need in order to work. 
*
*                   This is the layout of the generated structure:
*
*                   typedef struct _pph_context{
*                     gfshare_ctx* share_context      = new share context
*                     uint8 threshold                 = threshold
*                     uint8 available_shares;         = MAX_NUMBER_OF_SHARES
*                     uint8 next_entry;               = 1
*                     bool is_unlocked;               = true   
*                     uint8 *AES_key;                 = will point to secret       
*                     uint8 *secret;                  = generated secret
*                     uint8 partial_bytes;            = partial_bytes
*                     pph_account_node* account_data; = NULL
*                   } pph_context;
*                
*
* INPUTS :
*   PARAMETERS:
*     uint8 threshold:            The threshold for this specific
*                                 password storage. This is, the minimum
*                                 number of shares needed to unlock the 
*                                 upon reloading. The valid ranges for the 
*                                 threshold go from 1 to MAX_NUMBER_OF_SHARES;
*                                 however, a value of 1 is a bad idea.
*
*     uint8 partial_bytes:        The number of hashed-bytes to leak in order 
*                                 to perform partial verification. If 
*                                 partial_bytes = 0, partial verification is 
*                                 disabled. Partial bytes should range from 0
*                                 to DIGEST_LENGTH
* OUTPUTS :
*   PARAMETERS:
*     None
*     
*   GLOBALS :
*     None
*   
*   RETURN :
*     Type:   pph_context         the resulting context or NULL when either
*                                 allocation fails or the input given is not
*                                 within the valid ranges.
*
* PROCESS :
*   1) verify arguments
*   2) allocate data structures
*   3) generate a custom random secret
*   4) initialize the rest of the values
*   5) initialize the secret generator.
*   7) return 
*
* CHANGES :
*     21/04/2014: secret is no longer a parameter
*/

pph_context* pph_init_context(uint8 threshold, uint8 partial_bytes) {


  pph_context *context;

  // this is a specific initialization constant
  unsigned char share_numbers[MAX_NUMBER_OF_SHARES];
  unsigned int i;
  
  

  // 1) CHECK ARGUMENT SANITY
  // threshold
  if(threshold == 0 || threshold > MAX_NUMBER_OF_SHARES) {
    
    return NULL;

  }

  if(partial_bytes > DIGEST_LENGTH) {
    
    return NULL;
    
  }


  // 2)INITIALIZE DATA STRUCTURES
  context = malloc(sizeof(*context));
  if(context == NULL) {
    
    return NULL;
    
  }

  context->threshold=threshold;
  
  // initialize the partial bytes offset, this will be used to limit the
  // length of the shares, and the length of the digest to xor/encrypt.
  context->partial_bytes=partial_bytes;



  // 3) generate random secret, we generate a random byte stream and append
  // half of the 16 byte hash to the end of it, we have chosen to use
  // only four hash bytes in order to have more random bytes. 
  context->secret = generate_pph_secret(
      SIGNATURE_RANDOM_BYTE_LENGTH-partial_bytes,
      SIGNATURE_HASH_BYTE_LENGTH);
  if(context->secret == NULL) {
    free(context);
    
    return NULL;
    
  }



  // 4) Initialize the rest of the values.
  context->available_shares = (uint8)MAX_NUMBER_OF_SHARES;

  // since this is a new context, it should be unlocked.
  context->is_unlocked = true; 

  // We are using the secret to encrypt thresholdless accounts, so we set the 
  // AES key to be the same as the secret. 
  context->AES_key = context->secret;

  // initialize the rest
  context->next_entry=1;
  context->account_data=NULL;



  // 5) Initialize share context
  for(i=0;i<MAX_NUMBER_OF_SHARES;i++) {
    share_numbers[i]=(unsigned char)i+1;
  }

  // Update the share context, the size of the shares is reduced by the number
  // or partial bytes.
  context->share_context = NULL;
  context->share_context = gfshare_ctx_init_enc( share_numbers,
                                                 MAX_NUMBER_OF_SHARES-1,
                                                 context->threshold,
                                                 SHARE_LENGTH-partial_bytes);
  if(context->share_context == NULL) {
    free(context->secret);
    free(context);
    
    return NULL;
    
  }
  
  
  gfshare_ctx_enc_setsecret(context->share_context, context->secret);
  
  // finish, return our product
  return context;
    
}





/*******************************************************************
* NAME :            pph_destroy_context
*
* DESCRIPTION :     Destroy an existing instance of pph_context, securely 
*                   destroying its resources.
*
*                   The structure will have to free the following elements 
*                   before it can be safely freed:
*
*                   typedef struct _pph_context{
*                     gfshare_ctx* share_context      = needs freeing
*                     uint8 threshold                 = 
*                     uint8 available_shares;         = 
*                     uint8 next_entry;               = 
*                     bool is_unlocked;               = 
*                     uint8 *AES_key;                 = needs freeing      
*                     uint8 *secret;                  = needs freeing
*                     uint8 partial_bytes;            = 
*                     pph_account_node* account_data; = needs freeing
*                   } pph_context;
*
*
* INPUTS :
*   PARAMETERS:
*     pph_context *context: the context to destroy
*
* OUTPUTS :
*   PARAMETERS:
*     pph_context *context: the context to free/destroy.    
*     
*   GLOBALS :
*     None
*   
*   RETURN :
*     Type:   PPH_ERROR     
*                    value:                     when:
*                   PPH_ERROR_OK                  the free process worked
*
*                   PPH_ERROR_BAD_PTR             if the pointer given is NULL 
* PROCESS :
*     Basically destroy pointers in the structure and then free the structure
*     itself, doing sanity checks in between child and parent structure 
*     destruction. 
*
* CHANGES :
*     (03/17/14): Account freeing is done now. 
*/

PPH_ERROR pph_destroy_context(pph_context *context){


  pph_account_node *current,*next;


  // check that we are given a valid pointer
  if(context == NULL){
    
    return PPH_BAD_PTR;
    
  }
  
  
  // do child freeing.
  if(context->secret !=NULL){
    free(context->secret);
  }


  if(context->account_data != NULL){
    next = context->account_data;
    while(next!=NULL){
      current=next;
      next=next->next;
      // free their entry list
      _destroy_entry_list(current->account.entries);
      free(current); 
    }
  }


  if(context->share_context!=NULL){
    gfshare_ctx_free(context->share_context);
  }
  
  
  // now it is safe to free the context
  free(context);

  return PPH_ERROR_OK;
    
}




/*******************************************************************
* NAME :            pph_create_account
*
* DESCRIPTION :     given a context and some other data, create a user
*                   entry in the polypasshash context with the desired 
*                   information.
*
* INPUTS :
*   PARAMETERS:
*     pph_context *ctx:                   This is the context in which the
*                                         account will be created
*     
*     const uint8 *username:              This is the desired username for the
*                                         new entry
*
*     const unsigned int username_length: the length of the username field,
*                                         this value should not exceed 
*                                         MAX_USERNAME_LENGTH.
*
*     const uint8 *password:              This is the password for the new entry
*
*     const unsgned int password_length:  The length of the password field, this
*                                         value should not exceed 
*                                         MAX_PASSWORD_LENGTH
*
*     uint8 shares:                       This is the amount of shares we decide 
*                                         to allocate to this new account. 
* OUTPUTS :
*   PARAMETERS:
*     None
*     
*   GLOBALS :
*     None
*   
*   RETURN :
*     Type: int PPH_ERROR     
*           Values:                       When:
*             PPH_ERROR_OK                 The credentials provided are correct
*             
*             PPH_BAD_PTR                  One of the fields is unallocated
*
*             PPH_ERROR_UNKNOWN            When something unexpected happens.
*
*             PPH_NO_MEM                   If malloc, calloc fails.
*
*             PPH_USERNAME_IS_TOO_LONG     When the value for username_length is
*                                          larger than MAX_USERNAME_LENGTH.
*
*             PPH_PASSWORD_IS_TOO_LONG     When the value for password_length is
*                                          larger than MAX_PASSWORD_LENGTH.
*
*             PPH_CONTEXT_IS_LOCKED        When the context is locked and, hence
*                                          he cannot create accounts
*
*             PPH_ACCOUNT_EXISTS          If the username provided already 
*                                          exists
*
* PROCESS :
*     1) Check for data sanity, and return errors
*     2) Check the type of account requested
*     3) Allocate a share/digest entry for the account
*     4) Initialize the account data with the information provided
*     5) Update the context information regarding the new account
*     6) return
*
* CHANGES :
*   Added support for different length accounts
*/

PPH_ERROR pph_create_account(pph_context *ctx, const uint8 *username,
                        const unsigned int username_length, 
                        const uint8 *password, 
                        const unsigned int password_length, uint8 shares){


  pph_account_node *node,*next;
  unsigned int length;
  unsigned int i;
  pph_entry *entry_node,*last_entry;
  uint8 current_entry;
  uint8 share_data[SHARE_LENGTH];
  uint8 resulting_hash[DIGEST_LENGTH];
  uint8 salt_buffer[MAX_SALT_LENGTH];

  
  
  // 1) SANITIZE INFORMATION
  // check password length
  if(password_length > MAX_PASSWORD_LENGTH-1){
    
    return PPH_PASSWORD_IS_TOO_LONG;
    
  }

  // check username length
  if(username_length > MAX_USERNAME_LENGTH-1){
    
    return PPH_USERNAME_IS_TOO_LONG;
    
  }

  // check share numbers, we don't check for 0 since that means thresholdless
  // accounts
  if(shares>MAX_NUMBER_OF_SHARES){
    
    return PPH_WRONG_SHARE_COUNT;
    
  }
  
  // check correct context pointer
  if(ctx == NULL){
    
    return PPH_BAD_PTR;
    
  }

  // check if we are able to get shares from the context vault
  if(ctx->is_unlocked != true || ctx->AES_key == NULL){
    
    return PPH_CONTEXT_IS_LOCKED;
    
  }

  // This while loop will traverse our accounts and check if the username is 
  // already taken.
  next = ctx->account_data;
  while(next!=NULL){
    node=next;
    next=next->next;
    // only compare them if their lengths match
    if(username_length==node->account.username_length && 
        !memcmp(node->account.username,username,username_length)){
    
      return PPH_ACCOUNT_EXISTS; 
    
    }
  }


  // 2) check for the type of account requested.
  
  // this will generate a share list for threshold accounts, we won't 
  // fall inside this loop for thresholdless accounts since shares is 0.
  last_entry = NULL;

  for(i=0;i<shares;i++){
    
    // 3) Allocate entries for each account
    // get a new share value
    gfshare_ctx_enc_getshare( ctx->share_context, ctx->next_entry,
        share_data);

    // get a salt for the password
    get_random_bytes(MAX_SALT_LENGTH, salt_buffer);

    // Try to get a new entry.
    entry_node=create_polyhashed_entry(password, password_length, salt_buffer,
        MAX_SALT_LENGTH, share_data, SHARE_LENGTH, ctx->partial_bytes);
    if(entry_node == NULL){
      _destroy_entry_list(last_entry);
    
      return PPH_NO_MEM;
    
    }
    
    // update the share number for this entry, and update the next available
    // share in a round robin fashion
    entry_node->share_number = ctx->next_entry;
    ctx->next_entry++;
    if(ctx->next_entry==0 || ctx->next_entry>=MAX_NUMBER_OF_SHARES){
      ctx->next_entry=1;
    }   

    // add the node to the list
    entry_node->next = last_entry;
    last_entry=entry_node;
  }

  // This if will check for thresholdless accounts, and will build a single 
  // entry for them.
  if(shares == 0){
  
    // 3) allocate an entry for each account
    // get a salt for the password
    get_random_bytes(MAX_SALT_LENGTH, salt_buffer); 
 
    // generate the entry
    entry_node = create_thresholdless_entry(password, password_length,
        salt_buffer, MAX_SALT_LENGTH, ctx->AES_key, DIGEST_LENGTH,
        ctx->partial_bytes);

    if(entry_node == NULL){
    
      return PPH_NO_MEM;
    
    }

    // we now have one share entry under this list, so we increment this
    // parameter.
    shares++;
  }
  
  // 4) Allocate the information for the account
  // allocate the account information, check for memory issues and return.
  node=malloc(sizeof(*node));
  if(node==NULL){
    // we should destroy the list we created now to avoid memory leaks
    _destroy_entry_list(entry_node);
    
    return PPH_NO_MEM;
    
  }

  // fill with the user entry with the rest of the account information.
  memcpy(node->account.username,username,username_length);
  node->account.number_of_entries = shares;
  node->account.username_length = username_length;
  node->account.entries = entry_node;

  // 5) add the resulting account to the current context.
  // append it to the context list, with the rest of thee users
  node->next = ctx->account_data;
  ctx->account_data = node;

  // 6) return.
  // everything is set!
    
  return PPH_ERROR_OK;
    
}




/*******************************************************************
* NAME :          pph_check_login  
*
* DESCRIPTION :   Check whether a username and password combination exists 
*                 inside the loaded PPH context.
*
* INPUTS :
*   PARAMETERS:
*     pph_context *ctx:     The context in which we are working
*
*     const char *username: The username attempt
*
*     unsigned int username_length: The length of the username field
*
*     const char *password: The password attempt
*
*     unsigned int password_length: the length of the password field
*
* OUTPUTS :
*   PARAMETERS:
*     None
*     
*   GLOBALS :
*     None
*   
*   RETURN :
*     Type: int PPH_ERROR     
*           Values:                         When:
*           PPH_ACCOUNT_IS_INVALID            The combination does not exist
*           
*           PPH_USERNAME_IS_TOO_LONG          The username won't fit in the 
*                                             buffer
*
*           PPH_PASSWORD_IS_TOO_LONG          The password won't fit in the 
*                                             buffer associated to it. 
*
*           PPH_BAD_PTR                       When pointers are null or out
*                                             of range
*
*           PPH_ERROR_UNKNOWN                 any time else
*           
* PROCESS :
*     1) Sanitize data and return errors
*     2) try to find username in the context
*     3) if found, decide how to verify his information based on the status
*         of the context (thresholdless, partial verif, etc.)
*     4) Do the corresponding check and return the proper error
*
* CHANGES :
*  (21/04/2014): Added support for non-null-terminated usernames and passwords.
*/

PPH_ERROR pph_check_login(pph_context *ctx, const char *username, 
                          unsigned int username_length, uint8 *password,
                          unsigned int password_length){
 

  // this will be used to iterate all the users 
  pph_account_node *search;
  pph_account_node *target = NULL; 
  
  // we will store the current share in this buffer for xor'ing   
  uint8 share_data[SHARE_LENGTH];  
  
  // we will calculate a "proposed hash" in this buffer  
  uint8 resulting_hash[DIGEST_LENGTH];
  uint8 salted_password[MAX_SALT_LENGTH+MAX_PASSWORD_LENGTH]; 
                                                      
  uint8 xored_hash[SHARE_LENGTH];

  // these are value holders to improve readability
  uint8 sharenumber;
  pph_entry *current_entry;
  unsigned int i;

  // this will hold an offset value for partial verification.
  unsigned int partial_bytes_offset;

  // openSSL managers.
  EVP_CIPHER_CTX de_ctx;
  int p_len,f_len;


  // 1) Sanitize data and return errors.
  // check for any improper pointers
  if(ctx == NULL || username == NULL || password == NULL){
    
    return PPH_BAD_PTR;
    
  }

  // if the length is too long for either field, return proper error.
  if(username_length > MAX_USERNAME_LENGTH){
    
    return PPH_USERNAME_IS_TOO_LONG;
    
  }
  
  // do the same for the password
  if(password_length > MAX_PASSWORD_LENGTH){
    
    return PPH_PASSWORD_IS_TOO_LONG;
    
  }

  // check if the context is locked and we lack partial bytes to check. If we
  // do not have enough partial bytes (at least one), we cannot do partial
  // verification
  if(ctx->is_unlocked != true && ctx->partial_bytes == 0){
    
    return PPH_CONTEXT_IS_LOCKED;
    
  }

  // check we have a thresholdless key
  if(ctx->AES_key == NULL && ctx->partial_bytes == 0){
    
    return PPH_CONTEXT_IS_LOCKED;
    
  }


  // 2) Try to find the user in our context.
  // search for our user, we search the entries with the same username length 
  // first, and then we check if the contents are the same. 
  search = ctx->account_data;
  while(search!=NULL){
    // we check lengths first and then compare what's in it. 
    if(username_length == search->account.username_length && 
        !memcmp(search->account.username,username,username_length)){
      target = search;
    }
    search=search->next;
  } 

  //i.e. we found no one
  if(target == NULL){ 
    
    return PPH_ACCOUNT_IS_INVALID;
    
  }

  
  // if we reach here, we should have enough resources to provide a login
  // functionality to the user.
  

  // 3) Try to verify the proper password for him.
  // first, check what type of account is this
  
  // this probably happens if data is inconsistent, but let's avoid
  // segmentation faults. 
  if(target->account.entries == NULL){
    
    return PPH_ERROR_UNKNOWN; 
    
  }


  // we get the first entry to check if this is a valid login, we could be 
  // thorough and check for each, but it looks like an overkill
  current_entry = target->account.entries;
  sharenumber = current_entry->share_number;
  partial_bytes_offset = DIGEST_LENGTH - ctx->partial_bytes;
  
  
  // if the context is not unlocked, we can only provide partial verification  
  if(ctx->is_unlocked != true){

    // partial bytes check
    // calculate the proposed digest, this means, calculate the hash with
    // the information just provided about the user. 
    memcpy(salted_password,current_entry->salt,current_entry->salt_length);
    memcpy(salted_password+current_entry->salt_length, password,
        current_entry->password_length);
    _calculate_digest(resulting_hash, salted_password, 
       current_entry->salt_length + password_length);
   
    // only compare the bytes that are not obscured by either AES or the 
    // share, we start from share_length-partial_bytes to share_length. 
    if(memcmp(resulting_hash+partial_bytes_offset,
          target->account.entries->polyhashed_value+partial_bytes_offset,
          ctx->partial_bytes)){
    
      return PPH_ACCOUNT_IS_INVALID;
    
    }
    
    return PPH_ERROR_OK;
    
  }

  // we are unlocked and hence we can provide full verification.
  else{ 
    // first, check if the account is a threshold or thresholdless account.
    if(sharenumber == 0){
      
      // if the sharenumber is 0 then we have a thresholdless account
      
      // now we should calculate the expected hash by deciphering the
      // information inside the context.
      EVP_CIPHER_CTX_init(&de_ctx);
      EVP_DecryptInit_ex(&de_ctx, EVP_aes_256_ctr(), NULL, ctx->AES_key, NULL);
      EVP_DecryptUpdate(&de_ctx, xored_hash, &p_len, 
          current_entry->polyhashed_value, partial_bytes_offset);
      EVP_DecryptFinal_ex(&de_ctx, xored_hash+p_len, &f_len);
      EVP_CIPHER_CTX_cleanup(&de_ctx);

      // append the unencrypted bytes if we have partial bytes. 
      for(i=p_len+f_len;i<DIGEST_LENGTH;i++){
        xored_hash[i] = current_entry->polyhashed_value[i];
      }

      // calculate the proposed digest with the parameters provided in
      // this function.
      memcpy(salted_password,current_entry->salt, current_entry->salt_length);
      memcpy(salted_password+current_entry->salt_length, password, 
          password_length); 
      _calculate_digest(resulting_hash, salted_password, 
          current_entry->salt_length + password_length);

      
      // 3) compare both, and they should match.
      if(memcmp(resulting_hash, xored_hash, DIGEST_LENGTH)){
    
        return PPH_ACCOUNT_IS_INVALID;
    
      }
    
      return PPH_ERROR_OK;
    
    }else{
    
      // we have a non thresholdless account instead, since the sharenumber is 
      // not 0
      gfshare_ctx_enc_getshare(ctx->share_context, sharenumber, share_data);

      // calculate the proposed digest with the salt from the account and
      // the password in the argument.
      memcpy(salted_password,current_entry->salt, current_entry->salt_length);
      memcpy(salted_password+current_entry->salt_length, password, 
          password_length); 
      _calculate_digest(resulting_hash, salted_password, 
          current_entry->salt_length + password_length);
      
      // xor the thing back to normal
      _xor_share_with_digest(xored_hash,current_entry->polyhashed_value,
          share_data, partial_bytes_offset);
      
      // add the partial bytes to the end of the digest.
      for(i=DIGEST_LENGTH-ctx->partial_bytes;i<DIGEST_LENGTH;i++){
        xored_hash[i] = target->account.entries->polyhashed_value[i];
      }
      
      // compare both.
      if(memcmp(resulting_hash, xored_hash, DIGEST_LENGTH)){
    
        return PPH_ACCOUNT_IS_INVALID;
    
      }
    
      return PPH_ERROR_OK; // this means, the login does match
    
    } 
  }

  // if we get to reach here, we where diverged from usual flow. 
    
  return PPH_ERROR_UNKNOWN;
    
}




/*******************************************************************
* NAME :          pph_unlock_password_data 
*
* DESCRIPTION :   given a context and pairs of usernames and passwords,
*                 unlock the password secret. 
*
* INPUTS :
*   PARAMETERS:
*     pph_context *ctx:                The context in which we are working
*
*     unsigned int username_count:     The length of the username/password arrays
*
*     const char *usernames:           The username attempts
*
*     unsigned int username_lengths[]: The length of the username fields,
*                                      in the same order as the usernames.
*
*     const char *passwords:           The password attempts
*
* OUTPUTS :
*   PARAMETERS:
*     type: pph_context             The context provided will be activated and
*                                   pointed to the secret if combination was 
*                                   successful
*     
*   GLOBALS :
*     None
*   
*   RETURN :
*     Type: int PPH_ERROR     
*           Values:                         When:
*           PPH_ACCOUNT_IS_INVALID            We couldn't recombine with the 
*                                             information given
*           
*           PPH_USERNAME_IS_TOO_LONG          The username won't fit in the
*                                             buffer allocated to it.
*
*           PPH_PASSOWRD_IS_TOO_LONG          The password won't fit in it's
*                                             assigned buffer
*
*           PPH_BAD_PTR                       When pointers are null or out
*                                             of range
*
*           PPH_ERROR_UNKNOWN                 any time else
*           
* PROCESS :
*     1) Verify input sanity
*     2) traverse user accounts searching for proposed username
*     3) produce shares out of the password digest
*     4) give shares to the recombination context
*     5) attempt recombination
*     6) verify correct recombination.
*     7) if successful, unlock the store
*     8) return error code
*
* CHANGES :
*     (03/25/14): Secret consistency check was added. 
*/

PPH_ERROR pph_unlock_password_data(pph_context *ctx,unsigned int username_count,
                          const uint8 *usernames[], 
                          unsigned int username_lengths[],
                          const uint8 *passwords[]){
  
  
  uint8 share_numbers[MAX_NUMBER_OF_SHARES];
  gfshare_ctx *G;
  unsigned int i;
  uint8 secret[SHARE_LENGTH];
  uint8 salted_password[MAX_USERNAME_LENGTH+MAX_SALT_LENGTH];
  uint8 estimated_digest[DIGEST_LENGTH];
  uint8 estimated_share[SHARE_LENGTH];
  pph_entry *entry; 
  pph_account_node *current_user;
  

  //sanitize the data.
  if(ctx == NULL || usernames == NULL || passwords == NULL || 
      username_lengths == NULL){
    
    return PPH_BAD_PTR;
    
  }

  if(username_count < ctx->threshold){
    
    return PPH_ACCOUNT_IS_INVALID;
    
  }


  // initialize the share numbers
  for(i=0;i<MAX_NUMBER_OF_SHARES;i++){
    share_numbers[i] = 0;
  }
  
  // initialize a recombination context
  G = gfshare_ctx_init_dec( share_numbers, MAX_NUMBER_OF_SHARES-1,
     SHARE_LENGTH-ctx->partial_bytes);


  // traverse our possible users
  current_user=ctx->account_data;
  while(current_user!=NULL){
    // check if each of the provided users is inside the context. We traverse
    // our user list inside the while, and compare against the provided users 
    // inside this for loop.
    for(i = 0; i<username_count;i++){

      //compare the proposed against existing users.
      if(username_lengths[i] == current_user->account.username_length &&
          (!memcmp(usernames[i],current_user->account.username,
            current_user->account.username_length))){

        // this is an existing user
        entry = current_user->account.entries;
        
        // check if he is a threshold account.
        if(entry->share_number != 0){
        
          // if he is a threshold account, we must attempt to reconstruct the
          // shares using their information, traverse his entries
          while(entry!=NULL){

            // calulate the digest given the password.
            memcpy(salted_password,entry->salt,entry->salt_length);
            memcpy(salted_password+entry->salt_length, passwords[i],
                entry->password_length);
            _calculate_digest(estimated_digest,salted_password,
             MAX_SALT_LENGTH + current_user->account.entries->password_length);

            // xor the obtained digest with the polyhashed value to obtain
            // our share.
            _xor_share_with_digest(estimated_share,entry->polyhashed_value,
                estimated_digest,SHARE_LENGTH-ctx->partial_bytes);
         
            // give share to the recombinator. 
            share_numbers[entry->share_number] = entry->share_number+1;
            gfshare_ctx_dec_giveshare(G, entry->share_number,estimated_share);

            // move to the next entry.
            entry = entry->next;
          }
        } 
      }
    } 
    current_user = current_user->next;
  }


  // now we attempt to recombine the secret, we have given him all of the 
  // obtained shares.
  gfshare_ctx_dec_newshares(G, share_numbers);
  gfshare_ctx_dec_extract(G, secret);

  // verify that we got a proper secret back.
  if(check_pph_secret(secret, SIGNATURE_RANDOM_BYTE_LENGTH-ctx->partial_bytes,
        SIGNATURE_HASH_BYTE_LENGTH) != PPH_ERROR_OK){
    
    return PPH_ACCOUNT_IS_INVALID;
    
  }

  // else, we have a correct secret and we will copy it back to the provided
  // context.
  if(ctx->secret == NULL){
    ctx->secret = calloc(sizeof(ctx->secret),SHARE_LENGTH-ctx->partial_bytes);
  }
  memcpy(ctx->secret,secret,SHARE_LENGTH-ctx->partial_bytes);

  // if the share context is not initialized, initialize one with the
  // information we have about our context. 
  if(ctx->share_context == NULL){
    for(i=0;i<MAX_NUMBER_OF_SHARES;i++){
      share_numbers[i]=(unsigned char)i+1;
    }
    ctx->share_context = gfshare_ctx_init_enc( share_numbers,
                                               MAX_NUMBER_OF_SHARES-1,
                                               ctx->threshold,
                                               SHARE_LENGTH-ctx->partial_bytes);
  }
  
  // we have an initialized share context, we set the recombined secret to it 
  // and set the unlock flag to one so it is ready to use.
  gfshare_ctx_enc_setsecret(ctx->share_context, ctx->secret);
  ctx->is_unlocked = true;
  ctx->AES_key = ctx->secret;
  
  return PPH_ERROR_OK;
    
}





/*******************************************************************
* NAME :          pph_store_context
*
* DESCRIPTION :   store the information of the working context into a file. 
*                 Elements as the secret and the share context are not stored.
*                 
*
* INPUTS :
*   PARAMETERS:
*     pph_context *ctx:              The context in which we are working
*
*     const unsigned char* filename: The filename of the datastore to use
* OUTPUTS :
*   PARAMETERS:
*     None
*     
*   GLOBALS :
*     None
*   
*   RETURN :
*     Type: int PPH_ERROR     
*           Values:                         When:
*           PPH_ERROR_OK                      When the file was stored 
*                                             successfully.
*
*           PPH_BAD_PTR                       When pointers are null or out
*                                             of range
*           
*           PPH_FILE_ERR                      when the file selected is non-
*                                             writable. 
*
*           PPH_ERROR_UNKNOWN                 any time else
*           
* PROCESS :
*     * Sanitize the data (unset flags, point secret to NULL)
*     * open the selected file.
*     * traverse the dynamic linked lists storing everything
*     * close the file, return appropriate error
*
* CHANGES :
*     None as of this version
*/

PPH_ERROR pph_store_context(pph_context *ctx, const unsigned char *filename){
  
  
  FILE *fp;
  pph_account_node *current_node;

  // we use a hard copy so we can mess with it without damaging the one from the
  // user, he might want to keep using it and we need to set some values before
  // writing. 
  pph_context context_to_store; 
  pph_entry *current_entry;  


  // 1) sanitize the data
  if(ctx == NULL || filename == NULL){
    
    return PPH_BAD_PTR;
    
  }
 

  // we backup the context so we can mess with it without breaking anything. 
  memcpy(&context_to_store,ctx,sizeof(*ctx));

  // NULL out the pointers, we won't store that, not even where it used to point
  context_to_store.share_context = NULL;
  context_to_store.AES_key = NULL;
  context_to_store.secret = NULL;
  context_to_store.account_data = NULL;

  // set this context's information to locked.
  context_to_store.is_unlocked = false; 


  // 2) open selected file
  fp=fopen(filename,"wb");
  if(fp==NULL){
    
    return PPH_FILE_ERR;
    
  }


  // 3) write the context
  fwrite(&context_to_store,sizeof(context_to_store),1,fp); 

  // traverse the list and write it too.
  current_node = ctx->account_data;
  while(current_node!=NULL){
    
    // write current node...
    fwrite(current_node,sizeof(*current_node),1,fp);
    
    current_entry = current_node->account.entries;
    while(current_entry != NULL){
      
      // write its entries
      fwrite(current_entry,sizeof(*current_entry),1,fp);
      current_entry = current_entry->next;
    }
    current_node = current_node->next;
  }


  // 4) close the file, return appropriate error
  fclose(fp);
    
  return PPH_ERROR_OK;
    
}





/*******************************************************************
* NAME :          pph_reload_context
*
* DESCRIPTION :   Reload a pph_context stored in a file, the secret is
*                 unknown and the structure is locked by default.
*                 pph_unlock_password_data should be called after this returns
*                 a valid pointer 
*
* INPUTS :
*   PARAMETERS:
*     const unsigned char* filename: The filename of the datastore to use
*
* OUTPUTS :
*   PARAMETERS:
*     None
*     
*   GLOBALS :
*     None
*   
*   RETURN :
*     Type: pph_context * 
*
*           Values:                         When:
*            NULL                             The file is not loadable
*                                             or data looks corrupted
*           
*            A valid pointer                  if everything went fine
* 
* PROCESS :
*     * Sanitize the data (check the string is a good string) 
*     * open the selected file.
*     * Build a dynamic list by traversing the file's contents
*     * close the file, return appropriate structure
*
* CHANGES :
*     None as of this version
*/

pph_context *pph_reload_context(const unsigned char *filename){


  FILE *fp;
  pph_context *loaded_context;
  pph_account_node *accounts,*last,account_buffer;
  pph_entry *entries, *last_entry, entry_buffer;
  unsigned int i;


  // 1) sanitize data
  if(filename == NULL){
    
    return NULL;
    
  }


  // 2) open selected file
  fp= fopen(filename,"rb");
  if(fp == NULL){
    
    return NULL;
    
  }
  

  // 3) load the context structure from the file. 
  loaded_context = malloc(sizeof(*loaded_context));
  if(loaded_context == NULL){
    
    return NULL;
    
  }

  fread(loaded_context,sizeof(*loaded_context),1,fp);
  
  // build the account and entry list out of the information from the file. 
  accounts = NULL;
  while(fread(&account_buffer,sizeof(account_buffer),1,fp) != 0){
    
    // read an account
    last = accounts;
    accounts = malloc(sizeof(account_buffer));
    memcpy(accounts,&account_buffer,sizeof(account_buffer));
    last_entry = NULL;
    for(i=0;i<account_buffer.account.number_of_entries;i++){
      
      // allocate the entry list for this account
      entries = malloc(sizeof(*entries));
      fread(entries,sizeof(*entries),1,fp);
      entries->next = last_entry;
      last_entry = entries;
    }
    accounts->account.entries = entries;
    accounts->next = last;
    last = accounts; 
  }
  loaded_context->account_data = accounts;
  

  // 4) close the file.
  fclose(fp);
    
  return loaded_context;
    
}





/*******************************************************************
* NAME :          PHS 
*
* DESCRIPTION :   Generate a password hash, given the password, and salt. 
*                 This is a "virtual" interface and functions as a proof of
*                 context for the password hashing competition. A context will
*                 be initialized upon calling, and will be destroyed upon
*                 return. No persistent setup is done in this function, and no
*                 accounts are created. 
*
* INPUTS :
*   PARAMETERS:
*     void *out:          The resulting hash buffer. The resulting hash will be
*                         copied here. 
*
*     size_t outlen:      The size of the hash to produce, this version only
*                         supports 32 byte-length outputs. 
*
*     const void *in:     The input password to hash.
*
*     size_t inlen:       The length of the input, the maximum supported length
*                         is 128.
*
*     const void *salt:   The salt to use with the password
*
*     size_t saltlen:     The length of the salt to use. The maximum supported
*                         length is 16
*
*     int tcost:          Time cost for this function. This parameter 
*                         translates directly to the threshold of the
*                         generated context. With a bigger threshold, the time
*                         to initialize a context rises. This value can't be 0.
*
*     int mcost:          Memory cost (unusable this time)
*
* OUTPUTS :
*   PARAMETERS:
*     None
*     
*   GLOBALS :
*     None
*   
*   RETURN :
*     Type: int
*
*           Values:                         When:
*            0                                On error ok. 
*
*            !=0                              In case of error.
* 
* PROCESS :
*     1) verify the input. 
*     2) Generate a pph_context if there is none in memory
*     3) Generate a polyhashed entry
*     4) Copy the polyhashed value to the output buffer
*     5) Return.
*
* CHANGES :
*     None as of this version
*/

int PHS(void *out, size_t outlen, const void *in, size_t inlen,
   const void* salt, size_t saltlen, int tcost, int mcost){
  

  static pph_context *context = NULL;
  pph_entry *generated_entry; 
  uint8 share[DIGEST_LENGTH];


  // check we are given proper pointers
  if(out == NULL || in == NULL || salt == NULL){
    
    return -1;
    
  }

  // we only support 32 byte digests at the moment.
  if(outlen != DIGEST_LENGTH){
    
    return -1;
    
  }

  // check the input length
  if(inlen < 1 || inlen > MAX_PASSWORD_LENGTH){
    
    return -1;
    
  }

  // check the salt length
  if(saltlen < 1 || saltlen > MAX_SALT_LENGTH){
    
    return -1;
    
  }

  if(tcost < 1 || tcost > MAX_NUMBER_OF_SHARES){
    
    return -1;
    
  }

  // remember, in our case, tcost maps directly to the threshold value, we also
  // decided to leave no partial bytes to have the whole hash protected by the
  // shares 
  context = pph_init_context(tcost,0);

  // get a share to xor it with the password
  gfshare_ctx_enc_getshare(context->share_context, context->next_entry, share);
  context->next_entry++;
  if(context->next_entry > MAX_NUMBER_OF_SHARES){
    context->next_entry = 0;
  }

  // generate an entry.
  generated_entry = create_polyhashed_entry( in, inlen, salt, saltlen,
      share, DIGEST_LENGTH, context->partial_bytes);

  // copy the resulting polyhash to the output
  memcpy(out, generated_entry->polyhashed_value, outlen);

  // free the generated entry
  free(generated_entry);
  pph_destroy_context(context);

  return 0;
    
}







// helper functions ///////////////////////


// this generates a random secret of the form [stream][streamhash], the 
// parameters are the length of each section of the secret

uint8 *generate_pph_secret(unsigned int stream_length,
    unsigned int hash_length){
  

  uint8 *secret;
  uint8 stream_digest[DIGEST_LENGTH];

  // sanitize data
  if(stream_length > DIGEST_LENGTH || stream_length < 1){
    
    return NULL;
    
  }

  if(hash_length > DIGEST_LENGTH || hash_length < 1){
    
    return NULL;
    
  }

  if(hash_length + stream_length > DIGEST_LENGTH){
    
    return NULL;
    
  }

  // allocate memory
  secret=malloc(sizeof(*secret)*DIGEST_LENGTH);
  if(secret == NULL){
    
    return NULL;
    
  }

  // generate a random stream
  get_random_bytes(stream_length, secret);
 
  // hash the rest of the 
  _calculate_digest(stream_digest, secret, stream_length);
  memcpy(secret + stream_length, stream_digest, hash_length);

  return secret;
    
}





// this checks whether a given secret complies with the pph_secret prototype
// ([stream][streamhash])

PPH_ERROR check_pph_secret(uint8 *secret, unsigned int stream_length, 
    unsigned int hash_bytes){
  
  uint8 stream_digest[DIGEST_LENGTH];


  // sanitize data
  if(stream_length > DIGEST_LENGTH || stream_length < 1){
    
    return PPH_VALUE_OUT_OF_RANGE;
    
  }

  if(hash_bytes > DIGEST_LENGTH || hash_bytes < 1){
    
    return PPH_VALUE_OUT_OF_RANGE;
    
  }

  if(hash_bytes + stream_length > DIGEST_LENGTH){
    
    return PPH_VALUE_OUT_OF_RANGE;
    
  }

  if(secret == NULL){
    
    return PPH_BAD_PTR;
    
  }


  // generate the digest for the stream.
  _calculate_digest(stream_digest, secret, stream_length);
  
  // compare both digests
  if(memcmp(stream_digest, secret+stream_length, hash_bytes) == 0){
    
    return PPH_ERROR_OK;
    
  }

  return PPH_SECRET_IS_INVALID;
    
}





// this function provides a polyhashed entry given the input

pph_entry *create_polyhashed_entry(uint8 *password, unsigned int
    password_length, uint8 *salt, unsigned int salt_length, uint8 *share,
    unsigned int share_length, unsigned int partial_bytes){


  pph_entry *entry_node = NULL;
  
  // we hold a buffer for the salted password.
  uint8 salted_password[MAX_SALT_LENGTH+MAX_PASSWORD_LENGTH]; 

  // check input pointers are correct
  if(password == NULL || salt == NULL || share == NULL){
    
    return NULL;
    
  }

  // check for valid lengths
  if(password_length > MAX_PASSWORD_LENGTH || salt_length > MAX_SALT_LENGTH){
    
    return NULL;
    
  }

  // check for valid lengths on the share information
  if(share_length > SHARE_LENGTH || partial_bytes > SHARE_LENGTH){
    
    return NULL;
    
  }

  entry_node = malloc(sizeof(*entry_node));
  if(entry_node==NULL){
    
    return NULL;

  }
    

  // update the salt value in the entry
  memcpy(entry_node->salt,salt, salt_length);
  entry_node->salt_length = salt_length;
  entry_node->password_length = password_length;

  // prepend the salt to the password
  memcpy(salted_password,salt,salt_length);
  memcpy(salted_password+salt_length, password, password_length);

  // hash the salted password
  _calculate_digest(entry_node->polyhashed_value, salted_password,
        salt_length + password_length);
  
  // xor the whole thing, with the share, we are doing operations in-place
  // to make everything faster
  _xor_share_with_digest(entry_node->polyhashed_value, share,
        entry_node->polyhashed_value, share_length-partial_bytes);
    
  return entry_node;
    
}





// this other function is the equivalent to the one in the top, but for
// thresholdless accounts.

pph_entry *create_thresholdless_entry(uint8 *password, unsigned int
    password_length, uint8* salt, unsigned int salt_length, uint8* AES_key,
    unsigned int key_length, unsigned int partial_bytes){


  pph_entry *entry_node = NULL;
  uint8 salted_password[MAX_SALT_LENGTH + MAX_PASSWORD_LENGTH];

  // openssl encryption contexts
  EVP_CIPHER_CTX en_ctx;
  int c_len,f_len;



  // check everything makes sense, nothing should point to null
  if(password == NULL || salt == NULL || AES_key == NULL){
    
    return NULL;
    
  }

  // check for password and pass lengths
  if(password_length > MAX_PASSWORD_LENGTH || salt_length > MAX_SALT_LENGTH){
    
    return NULL;
    
  }

  // we check that the key is shorter than the digest we are using for
  // ctr mode, but we could omit this, partial bytes should be shorter
  // than the digest length since we cannot reveal more bytes than the ones
  // we have.
  if(key_length > DIGEST_LENGTH || partial_bytes > DIGEST_LENGTH){
    
    return NULL;
    
  }

  // allocate memory and fail if there is not memory available.
  entry_node = malloc(sizeof(*entry_node));
  if(entry_node==NULL){
    
    return NULL;
    
  }

  // copy the salt into the pph_entry
  memcpy(entry_node->salt, salt, salt_length);
  entry_node->salt_length = salt_length;
  
  // prepend the salt to the password and generate a digest
  memcpy(salted_password,entry_node->salt,salt_length);
  memcpy(salted_password+MAX_SALT_LENGTH, password, password_length); 
  _calculate_digest(entry_node->polyhashed_value,salted_password, 
      salt_length + password_length); 

  // encrypt the generated digest
  EVP_CIPHER_CTX_init(&en_ctx);
  EVP_EncryptInit_ex(&en_ctx, EVP_aes_256_ctr(), NULL, AES_key, NULL);
  EVP_EncryptUpdate(&en_ctx, entry_node->polyhashed_value, &c_len,
      entry_node->polyhashed_value, DIGEST_LENGTH-partial_bytes);
  EVP_EncryptFinal_ex(&en_ctx, entry_node->polyhashed_value+c_len, &f_len);
  EVP_CIPHER_CTX_cleanup(&en_ctx);


  // thresholdless accounts have this value defaulted to 0;
  entry_node->share_number = 0;

  // thresholdless accounts should have only one entry
  entry_node->next = NULL;

  return entry_node;  

}






// This is a private helper that produces a salt string,

void get_random_bytes(unsigned int length, uint8 *dest){
    
    
  unsigned int i=0;
  int fp;

    
  fp = open("/dev/urandom",O_RDONLY);
  while(i<length){
    i += read(fp,dest,length);
  }
  close(fp);

}


