/* Check libpolypasshash with partial bytes. 
 *
 * check the partial bytes extension of the libpolypasshash module. 
 *
 * @author  Santiago Torres
 * @date    10/03/2014
 * @license MIT
 */


#include<check.h>
#include"libgfshare.h"
#include"libpolypasshash.h"
#include<stdlib.h>
#include<strings.h>





// we test that init context will provide a correct value with the partial 
// bytes value set to something different than 0
START_TEST(test_pph_init_context_partial_bytes)
{ 
  
  
  pph_context *context; 
  uint8 threshold = 2;  
  uint8 partial_bytes = 2;


  context = pph_init_context(threshold, partial_bytes);

  ck_assert_msg( context != NULL, " couldn't initialize the pph context" );
  ck_assert_msg( context->AES_key != NULL, "the key wansn't generated properly");
  ck_assert_msg( context->partial_bytes == partial_bytes,
      "didn't set partial bytes properly");

}
END_TEST

// we check that destroy context is working too. This shouldn't be a problem.
START_TEST(test_pph_destroy_context_partial_bytes)
{
  
  
  pph_context *context;
  PPH_ERROR error;
  uint8 threshold = 2; 
  uint8 partial_bytes = 2;
                          

  context = pph_init_context(threshold, partial_bytes);
  ck_assert_msg(context != NULL, " shouldn't break here");

  error = pph_destroy_context(context);
  ck_assert(error == PPH_ERROR_OK); 

}
END_TEST





// Test create accounts with thresholdless accounts and partial bytes. 
START_TEST(test_pph_create_accounts)
{


  PPH_ERROR error;
  pph_context *context;
  uint8 threshold = 2; 
  uint8 partial_bytes = 2;
                          
  unsigned char password[] = "verysecure";
  unsigned char username[] = "atleastitry";
  uint8 password_digest[DIGEST_LENGTH]; 
  unsigned int i;


  context = pph_init_context(threshold, partial_bytes);
  ck_assert_msg(context != NULL,
      "this was a good initialization, go tell someone");
  
  // create a thresholdless account with partial bytes.
  error = pph_create_account(context, username, strlen(username), password,
      strlen(password), 0); 
  ck_assert_msg(error == PPH_ERROR_OK, 
      "We should have gotten PPH_ERROR_OK in the return value");
  
  // check the username matches. 
  ck_assert_str_eq(username,context->account_data->account.username);

  // now lets check there are collisions between threshold and thresholdless
  // accounts
  error = pph_create_account(context, username, strlen(username), password,
      strlen(password), 1);
  ck_assert_msg(error == PPH_ACCOUNT_EXISTS, 
      "We should have gotten an error since this account repeats");
  
  // finally, check it returns the proper error code if the vault is locked
  // still, we will set the key to null and the locked flag to 0 to simulate
  // this.
  context->is_unlocked = false; 
  context->AES_key = NULL;

  // we will check for the existing account error handler now...
  error = pph_create_account(context, "someotherguy", strlen("someotherguy"),
   "came-here-asking-the-same-thing",strlen("came-here-asking-the-same-thing"),
   0);
  ck_assert_msg(error == PPH_CONTEXT_IS_LOCKED, 
      "We should have gotten an error now that the vault is locked");
 
  error = pph_destroy_context(context);
  ck_assert_msg(error == PPH_ERROR_OK, 
      "the free function didn't work properly");
}
END_TEST





// We check for both, thresholdless accounts and threshold accounts under 
// partial bytes setup.
START_TEST(test_create_account_mixed_accounts) {
  
  
  PPH_ERROR error;
  pph_context *context;
  uint8 threshold = 2; 
  uint8 partial_bytes = 2;
  unsigned char password[] = "verysecure";
  unsigned char username[] = "atleastitry";
  
  
  context = pph_init_context(threshold, partial_bytes);
  ck_assert_msg(context != NULL,
      "this was a good initialization, go tell someone");
  
  // create a thresholdless account.
  error = pph_create_account(context, username, strlen(username), password,
      strlen(password), 0); // THL account. 
  ck_assert_msg(error == PPH_ERROR_OK, 
      "We should've gotten PPH_ERROR_OK in the return value");
  
  // check that we get a valid username for this. 
  ck_assert_str_eq(username,context->account_data->account.username);
  
  
  // now let's create a bunch of accounts with thresholds this time
  error = pph_create_account(context, "johhnyjoe", strlen("johhnyjoe"),
      "passwording", strlen("passwording"),1);
  ck_assert_msg(error == PPH_ERROR_OK, 
      "We should have gotten PPH_ERROR_OK in the return value");
  error = pph_create_account(context, "richardWalkins", strlen("richardWalkins"),
      "i'm-unreliable",strlen("i'm-unreliable"),5);
  ck_assert_msg(error == PPH_ERROR_OK, 
      "We should have gotten PPH_ERROR_OK in the return value");
  
  pph_destroy_context(context); 
}
END_TEST





// This checks for a proper behavior when providing an existing username, 
// first, as the first and only username, then after having many on the list
START_TEST(test_check_login_thresholdless) {


  PPH_ERROR error;
  pph_context *context;
  uint8 threshold = 2; 
  uint8 partial_bytes = 2;
  unsigned char password[] = "i'mnothere";
  unsigned char username[] = "nonexistentpassword";
  unsigned char anotheruser[] = "0anotheruser";
  unsigned int i;

  
  // setup the context 
  context = pph_init_context(threshold, partial_bytes);
  ck_assert_msg(context != NULL,
      "this was a good initialization, go tell someone");
  

  // add a single user and see how it behaves:
  // 1) add a user
  error = pph_create_account(context, username, strlen(username), password,
     strlen(password), 0);
  ck_assert_msg(error == PPH_ERROR_OK, " this shouldn't have broken the test");

  // 2) ask for it, providing correct credentials
  error = pph_check_login(context, username, strlen(username), password,
      strlen(password));
  ck_assert_msg(error == PPH_ERROR_OK, 
      "expected OK");
  
  
  // lets add a whole bunch of users and check for an existing one again
  // 1) add a whole new bunch of users:
  for(i=1;i<9;i++) {
    error = pph_create_account(context, anotheruser, strlen(anotheruser),
        "anotherpassword", strlen("anotherpassword"), 1);
    ck_assert_msg(error == PPH_ERROR_OK,
        " this shouldn't have broken the test");
    anotheruser[0] = i+48;
  }

  // 2) ask again
  error = pph_check_login(context, username, strlen(username), password,
      strlen(password));
  ck_assert_msg(error == PPH_ERROR_OK, 
      "expected ERROR_OK");
  
  // 3) ask one more time, mistyping our passwords
  error = pph_check_login(context, username, strlen(username), "i'mnotthere",
      strlen("i'mnotthere"));
  ck_assert_msg(error == PPH_ACCOUNT_IS_INVALID, " how did we get in!?");

  // 4) check if threshold accounts can login (they should)
  error = pph_check_login(context, "0anotheruser", strlen("0anotheruser"),
      "anotherpassword", strlen("anotherpassword"));
  ck_assert_msg(error == PPH_ERROR_OK,
      " we should've been able to login as admin");

  // clean up our mess.
  pph_destroy_context(context);
}
END_TEST




// we test partial verification, we use a seemingly locked context and try to
// login. We don't care if the account is thresholdless or threshold, since
// we only check for the leaked partial bytes. 
START_TEST(test_pph_partial_verification_and_unlock) {


  PPH_ERROR error;
  pph_context *context;
  uint8 threshold = 2; 
  uint8 partial_bytes = 2;
                         
  unsigned int i;
  unsigned int username_count=5;
  const uint8 *usernames[] = {"username1",
                              "username12",
                              "username1231",
                              "username26",
                              "username5",
                            };
  const uint8 *passwords[] = {"password1",
                              "password12",
                              "password1231",
                              "password26",
                              "password5"
                              };
  unsigned int username_lengths[] = { strlen("username1"),
                                      strlen("username12"),
                                      strlen("username1231"),
                                      strlen("username26"),
                                      strlen("username5"),
                                  };
  const uint8 *usernames_subset[] = { "username12",
                                      "username26"};
  unsigned int username_lengths_subset[] = { strlen("username12"),
                                            strlen("username26"),
                                            };


  const uint8 *password_subset[] = { "password12",
                                     "password26"};

  
  // check for bad pointers at first
  error = pph_unlock_password_data(NULL, username_count, usernames, 
      username_lengths, passwords);
  ck_assert_msg(error == PPH_BAD_PTR," EXPECTED BAD_PTR");

  // setup the context 
  context = pph_init_context(threshold, partial_bytes);
  ck_assert_msg(context != NULL,
      "this was a good initialization, go tell someone");
  
  // store the accounts
  for(i=0;i<username_count;i++) {
    error = pph_create_account(context, usernames[i], strlen(usernames[i]),
        passwords[i], strlen(passwords[i]),1);
    ck_assert(error == PPH_ERROR_OK);
  }
  
  // let's pretend all is broken
  context->is_unlocked = false;
  context->AES_key = NULL;
  context->secret = NULL;
  context->share_context= NULL;

  // now try to login properly with partial verification
  error = pph_check_login(context, usernames[0], strlen(usernames[0]), 
        passwords[0], strlen(passwords[0]));
  ck_assert(error == PPH_ERROR_OK);

  // now let's see if we can try to login with a wrong password, we shouldn't
  error = pph_check_login(context, usernames[0], strlen(usernames[0]),
        "wrongpass", strlen("wrongpass"));
  ck_assert(error == PPH_ACCOUNT_IS_INVALID);

  // now give a wrong username count, i.e. below the threshold.
  error = pph_unlock_password_data(context, 0, usernames, 
      username_lengths, passwords);
  ck_assert_msg(error == PPH_ACCOUNT_IS_INVALID, 
      " Expected ACCOUNT_IS_INVALID");

  // do it again, more graphical... 
  error = pph_unlock_password_data(context, threshold -1, usernames, 
      username_lengths, passwords);
  ck_assert_msg(error == PPH_ACCOUNT_IS_INVALID, 
      " Expected ACCOUNT_IS_INVALID");

  // let's check for NULL pointers on the username and password fields
  error = pph_unlock_password_data(context, username_count, NULL,
     username_lengths, passwords);
  ck_assert_msg(error == PPH_BAD_PTR," EXPECTED BAD_PTR");

 
  // let's check for NULL pointers on the username and password fields
  error = pph_unlock_password_data(context, username_count, usernames, 
      username_lengths, NULL);
  ck_assert_msg(error == PPH_BAD_PTR," EXPECTED BAD_PTR");


  // now give a correct full account information, we expect to have our secret
  // back. 
  error = pph_unlock_password_data(context, username_count, usernames,
      username_lengths, passwords);
  ck_assert(error == PPH_ERROR_OK);
  ck_assert_msg(context->secret !=NULL, " didnt allocate the secret!");
  ck_assert(context->AES_key != NULL);

  // let's imagine it's all broken (Again).
  context->is_unlocked = false;
  context->AES_key = NULL;
  context->secret = NULL;
  context->share_context = NULL;

  // now give correct account information, we expect to have our secret
  // back. 
  error = pph_unlock_password_data(context, 2, usernames_subset,
      username_lengths_subset, password_subset);
  ck_assert(error == PPH_ERROR_OK);
  ck_assert(context->AES_key != NULL);


  // for the sake of it, let's login with a correct account after the
  // secret was recombined.
  error = pph_check_login(context, usernames_subset[0], 
      strlen(usernames_subset[0]),password_subset[0], strlen(password_subset[0]));
  ck_assert(error == PPH_ERROR_OK);

  pph_destroy_context(context);
}
END_TEST





// suite definition
Suite * polypasshash_partial_bytes_suite(void)
{
  
  
  Suite *s = suite_create ("partial_bytes");

  /*partial bytes case */
  TCase *tc_partial = tcase_create ("partial");
  tcase_add_test (tc_partial,test_pph_init_context_partial_bytes);
  tcase_add_test (tc_partial,test_pph_destroy_context_partial_bytes);
  tcase_add_test (tc_partial,test_pph_create_accounts);
  tcase_add_test (tc_partial,test_create_account_mixed_accounts);
  tcase_add_test (tc_partial,test_check_login_thresholdless);
  tcase_add_test (tc_partial,test_pph_partial_verification_and_unlock);
  suite_add_tcase (s, tc_partial);

  return s;
}




// suite runner setup
int main (void)
{
  int number_failed;
  Suite *s =  polypasshash_partial_bytes_suite();
  SRunner *sr = srunner_create (s);
  srunner_run_all (sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed (sr);
  srunner_free (sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


