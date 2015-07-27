/*
 * sig_client.c
 *
 * Authors: Alec Guertin (skeleton), Paul Mercurio, Sean Murphy (implementation)
 * University of California, Berkeley
 * CS 161 - Computer Security
 * Fall 2014 Semester
 * Project 1
 */

#include "client.h"

/* The file descriptor for the socket connected to the server. */
static int sockfd;

static void perform_rsa(mpz_t result, mpz_t message, mpz_t e, mpz_t n);
static int hex_to_ascii(char a, char b);
static int hex_to_int(char a);
static void usage();
static void kill_handler(int signum);
static int random_int();
static void cleanup();

int main(int argc, char **argv) {
  int err, option_index, c, clientlen, counter;
  unsigned char rcv_plaintext[AES_BLOCK_SIZE];
  unsigned char rcv_ciphertext[AES_BLOCK_SIZE];
  unsigned char send_plaintext[AES_BLOCK_SIZE];
  unsigned char send_ciphertext[AES_BLOCK_SIZE];
  aes_context enc_ctx, dec_ctx;
  in_addr_t ip_addr;
  struct sockaddr_in server_addr;
  FILE *c_file, *d_file, *m_file;
  ssize_t read_size, write_size;
  struct sockaddr_in client_addr;
  tls_msg err_msg, send_msg, rcv_msg;
  mpz_t client_exp, client_mod;
  fd_set readfds;
  struct timeval tv;

  c_file = d_file = m_file = NULL;

  mpz_init(client_exp);
  mpz_init(client_mod);

  /*
   * This section is networking code that you don't need to worry about.
   * Look further down in the function for your part.
   */

  memset(&ip_addr, 0, sizeof(in_addr_t));

  option_index = 0;
  err = 0;

  static struct option long_options[] = {
    {"ip", required_argument, 0, 'i'},
    {"cert", required_argument, 0, 'c'},
    {"exponent", required_argument, 0, 'd'},
    {"modulus", required_argument, 0, 'm'},
    {0, 0, 0, 0},
  };

  while (1) {
    c = getopt_long(argc, argv, "c:i:d:m:", long_options, &option_index);
    if (c < 0) {
      break;
    }
    switch(c) {
    case 0:
      usage();
      break;
    case 'c':
      c_file = fopen(optarg, "r");
      if (c_file == NULL) {
	perror("Certificate file error");
	exit(1);
      }
      break;
    case 'd':
      d_file = fopen(optarg, "r");
      if (d_file == NULL) {
	perror("Exponent file error");
	exit(1);
      }
      break;
    case 'i':
      ip_addr = inet_addr(optarg);
      break;
    case 'm':
      m_file = fopen(optarg, "r");
      if (m_file == NULL) {
	perror("Modulus file error");
	exit(1);
      }
      break;
    case '?':
      usage();
      break;
    default:
      usage();
      break;
    }
  }

  if (d_file == NULL || c_file == NULL || m_file == NULL) {
    usage();
  }
  if (argc != 9) {
    usage();
  }

  mpz_inp_str(client_exp, d_file, 0);
  mpz_inp_str(client_mod, m_file, 0);


  signal(SIGTERM, kill_handler);

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    perror("Could not open socket");
    exit(1);
  }

  memset(&server_addr, 0, sizeof(struct sockaddr_in));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = ip_addr;
  server_addr.sin_port = htons(HANDSHAKE_PORT);
  err = connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr));
  if (err < 0) {
    perror("Could not bind socket!");
    cleanup();
  }

  // YOUR CODE HERE
  // IMPLEMENT THE TLS HANDSHAKE
  //////////////////////////////////////////////////////////////////////////////////////////////////////////////

  hello_message *m = malloc(1 * HELLO_MSG_SIZE);
  hello_message *r = malloc(1 * HELLO_MSG_SIZE);
  m->type = CLIENT_HELLO;
  m->random = random_int();
  m->cipher_suite = TLS_RSA_WITH_AES_128_ECB_SHA256;
  send_tls_message(sockfd, m, HELLO_MSG_SIZE); //client hello
  receive_tls_message(sockfd, r, HELLO_MSG_SIZE, SERVER_HELLO); //server hello
  printf("m.type = %d, m.rand = %d, m.cipher = %d   ----Client Hello\n", m->type, m->random, m->cipher_suite);
  printf("r.type = %d, r.rand = %d, r.cipher = %d   ----Server Hello\n", r->type, r->random, r->cipher_suite);

  //////////////////////////////////////////////////////////////////////////////////////////////////////////////

  cert_message *m_cert, *r_cert;
  m_cert = malloc(1 * CERT_MSG_SIZE);
  r_cert = malloc(1 * CERT_MSG_SIZE);
  m_cert->type = CLIENT_CERTIFICATE;
  fread(m_cert->cert, RSA_MAX_LEN+1, 1, c_file);
  send_tls_message(sockfd, m_cert, CERT_MSG_SIZE);
  receive_tls_message(sockfd, r_cert, CERT_MSG_SIZE, SERVER_CERTIFICATE);
  printf("m_cert.type = %d, m_cert.cert = long stuff...   ----Client Certificate\n", m_cert->type);
  printf("r_cert.type = %d, r_cert.cert = long stuff...   ----Server Certificate\n", r_cert->type);

  //////////////////////////////////////////////////////////////////////////////////////////////////////////////

  mpz_t decrypted_cert, ca_exp, ca_mod;
  mpz_init(decrypted_cert);
  mpz_init(ca_exp);
  mpz_init(ca_mod);
  mpz_set_str(ca_exp, CA_EXPONENT, 0);
  mpz_set_str(ca_mod, CA_MODULUS, 0);

  decrypt_cert(decrypted_cert, r_cert, ca_exp, ca_mod);

  // mpz_clear(ca_mod);
  // mpz_clear(ca_exp);

  char* decrypt_cert_pointer = malloc( 1 * sizeof(decrypted_cert));

  // mpz_t my_key;
  // mpz_init_set(my_key, client_exp);

  mpz_get_ascii(decrypt_cert_pointer, decrypted_cert);

  mpz_clear(decrypted_cert);

  mpz_t result_exponent, result_mod;
  mpz_init(result_exponent);
  mpz_init(result_mod);

  get_cert_modulus(result_mod, decrypt_cert_pointer);
  get_cert_exponent(result_exponent, decrypt_cert_pointer);


  // Initialize premaster/master secret vars..
  ps_msg *m_premaster, *r_master;
  m_premaster = malloc(1 * PS_MSG_SIZE);
  r_master = malloc(1 * PS_MSG_SIZE);
  m_premaster->type = PREMASTER_SECRET;
  char *master_secret_array;
  master_secret_array = malloc(16 * BYTE_SIZE);
  memset(master_secret_array, 0, 16);
  mpz_t the_premaster_secret, the_master_secret, encrypted_pm_secret, decrypted_master_secret;
  mpz_init(the_premaster_secret);
  mpz_init(encrypted_pm_secret);

  // Randomly generate premaster secret
  unsigned int premaster_int = random_int();
  mpz_set_ui(the_premaster_secret, premaster_int);

  // Encrypt/Send the premaster secret
  perform_rsa(encrypted_pm_secret, the_premaster_secret, result_exponent, result_mod);
  mpz_get_str(m_premaster->ps, 16, encrypted_pm_secret);
  gmp_printf("Set m_premaster.ps to encrypted pm value for server...\n");

  mpz_clear(encrypted_pm_secret);
    
  send_tls_message(sockfd, m_premaster, PS_MSG_SIZE);
  printf("m_premaster.type = %d, m_premaster.ps = long stuff...   ----Client Encrypted Premaster\n", m_premaster->type);
    
  // Receive server's encrypted version of master secret...
  receive_tls_message(sockfd, r_master, PS_MSG_SIZE, VERIFY_MASTER_SECRET);
  printf("r_master.type = %d, r_master.ps = long stuff...   ----Server Encrypted Master\n", r_master->type);
  printf("The encrypted master secret is: %s\n",r_master->ps);
    
  // Decrypt the master secret
  mpz_init(the_master_secret);
  mpz_init(decrypted_master_secret);

  decrypt_verify_master_secret(decrypted_master_secret, r_master, client_exp, client_mod);

  char* decrypted_master_secret_array;
  decrypted_master_secret_array = malloc(32*BYTE_SIZE);
  mpz_get_str(decrypted_master_secret_array, 16, decrypted_master_secret);


  // Calculate our version of master secret...
  compute_master_secret(premaster_int, m->random, r->random, master_secret_array);
  printf("Just computed our master secret..\n");
    
  // Compare our version of master secret with server's version...
  printf("Before Comparison:\n");
  printf("decrypted_master_secret_array: %s\n", decrypted_master_secret_array);
  printf("master_secret_array          : %s\n", master_secret_array);
    
  if (strcmp(decrypted_master_secret_array, master_secret_array) != 0) {
      perror("Master secrets do not match!!\n");
      cleanup();
  }
  else {
      printf("Master secrets match YAY!\n");
  }

  /*
   * START ENCRYPTED MESSAGES
   */

  memset(send_plaintext, 0, AES_BLOCK_SIZE);
  memset(send_ciphertext, 0, AES_BLOCK_SIZE);
  memset(rcv_plaintext, 0, AES_BLOCK_SIZE);
  memset(rcv_ciphertext, 0, AES_BLOCK_SIZE);

  memset(&rcv_msg, 0, TLS_MSG_SIZE);

  aes_init(&enc_ctx);
  aes_init(&dec_ctx);
  
  // YOUR CODE HERE
  // SET AES KEYS
    
  //char* final;
  //final = malloc(16*BYTE_SIZE);
  //memset(final, 0, 16);
  unsigned char final[16];
  
  printf("Now enter conversion loop...\n");
    
  int p;
  int k = 0;
  for (p = 0; p < 32; p += 2) {
      char temps[2];
      sprintf(temps, "%c%c",*(decrypted_master_secret_array+p),*(decrypted_master_secret_array+p+1));
      printf("%s ",temps);
      int temp = strtol(temps,NULL,16);
      final[k] = temp;
      k++;
  }
  printf("\n");
  printf("FINAL: %s\n",final);
    
  if (aes_setkey_enc (&enc_ctx, final, 128)) {
      printf("Error setting AES encryption key!\n");
      cleanup();
  }
  if (aes_setkey_dec (&dec_ctx, final, 128)) {
      printf("Error setting AES decryption key!\n");
      cleanup();
  }
  printf("Done setting AES keys...\n");

  ///////////////////////////////////////////////////////////////////////////

  fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
  /* Send and receive data. */
  while (1) {
    FD_ZERO(&readfds);
    FD_SET(STDIN_FILENO, &readfds);
    FD_SET(sockfd, &readfds);
    tv.tv_sec = 2;
    tv.tv_usec = 10;

    select(sockfd+1, &readfds, NULL, NULL, &tv);
    if (FD_ISSET(STDIN_FILENO, &readfds)) {
      counter = 0;
      memset(&send_msg, 0, TLS_MSG_SIZE);
      send_msg.type = ENCRYPTED_MESSAGE;
      memset(send_plaintext, 0, AES_BLOCK_SIZE);
      read_size = read(STDIN_FILENO, send_plaintext, AES_BLOCK_SIZE);
      while (read_size > 0 && counter + AES_BLOCK_SIZE < TLS_MSG_SIZE - INT_SIZE) {
	if (read_size > 0) {
	  err = aes_crypt_ecb(&enc_ctx, AES_ENCRYPT, send_plaintext, send_ciphertext);
	  memcpy(send_msg.msg + counter, send_ciphertext, AES_BLOCK_SIZE);
	  counter += AES_BLOCK_SIZE;
	}
	memset(send_plaintext, 0, AES_BLOCK_SIZE);
	read_size = read(STDIN_FILENO, send_plaintext, AES_BLOCK_SIZE);
      }
      write_size = write(sockfd, &send_msg, INT_SIZE+counter+AES_BLOCK_SIZE);
      if (write_size < 0) {
	perror("Could not write to socket");
	cleanup();
      }
    } else if (FD_ISSET(sockfd, &readfds)) {
      memset(&rcv_msg, 0, TLS_MSG_SIZE);
      memset(rcv_ciphertext, 0, AES_BLOCK_SIZE);
      read_size = read(sockfd, &rcv_msg, TLS_MSG_SIZE);
      if (read_size > 0) {
	if (rcv_msg.type != ENCRYPTED_MESSAGE) {
	  goto out;
	}
	memcpy(rcv_ciphertext, rcv_msg.msg, AES_BLOCK_SIZE);
	counter = 0;
	while (counter < read_size - INT_SIZE - AES_BLOCK_SIZE) {
	  aes_crypt_ecb(&dec_ctx, AES_DECRYPT, rcv_ciphertext, rcv_plaintext);
	  printf("%s", rcv_plaintext);
	  counter += AES_BLOCK_SIZE;
	  memcpy(rcv_ciphertext, rcv_msg.msg+counter, AES_BLOCK_SIZE);
	}
    printf("\n");
      }
    }

  }

 out:
  close(sockfd);
  return 0;
}

/*
 * \brief                  Decrypts the certificate in the message cert.
 *
 * \param decrypted_cert   This mpz_t stores the final value of the binary
 *                         for the decrypted certificate. Write the end
 *                         result here.
 * \param cert             The message containing the encrypted certificate.
 * \param key_exp          The exponent of the public key for decrypting
 *                         the certificate.
 * \param key_mod          The modulus of the public key for decrypting
 *                         the certificate.
 */
void
decrypt_cert(mpz_t decrypted_cert, cert_message *cert, mpz_t key_exp, mpz_t key_mod)
{
  // YOUR CODE HERE
  char* cert_pointer = &(cert->cert[0]);

  mpz_t crypted_cert;
  mpz_init(crypted_cert);
  mpz_set_str(crypted_cert, cert_pointer, 0);

  perform_rsa(decrypted_cert, crypted_cert, key_exp, key_mod);

  mpz_clear(crypted_cert);
}

/*
 * \brief                  Decrypts the master secret in the message ms_ver.
 *
 * \param decrypted_ms     This mpz_t stores the final value of the binary
 *                         for the decrypted master secret. Write the end
 *                         result here.
 * \param ms_ver           The message containing the encrypted master secret.
 * \param key_exp          The exponent of the public key for decrypting
 *                         the master secret.
 * \param key_mod          The modulus of the public key for decrypting
 *                         the master secret.
 */
void
decrypt_verify_master_secret(mpz_t decrypted_ms, ps_msg *ms_ver, mpz_t key_exp, mpz_t key_mod)
{
  printf("Now decrypting server's master secret...\n");
  char hex_pointer[RSA_MAX_LEN+2];
  strcpy(hex_pointer,  "0x");
  char* ms_pointer = &(ms_ver->ps[0]);
  strcat(hex_pointer, ms_pointer);

  mpz_t encrypted_master_secret;
  mpz_init(encrypted_master_secret);

  mpz_set_str(encrypted_master_secret, hex_pointer, 0);
  gmp_printf("The encrypted master secret mpz is: %Zd\n",encrypted_master_secret);

  perform_rsa(decrypted_ms, encrypted_master_secret, key_exp, key_mod);
  gmp_printf("The decrypted master secret is: %Zd\n",decrypted_ms);
  mpz_clear(encrypted_master_secret);
}

/*
 * \brief                  Computes the master secret.
 *
 * \param ps               The premaster secret.
 * \param client_random    The random value from the client hello.
 * \param server_random    The random value from the server hello.
 * \param master_secret    A pointer to the final value of the master secret.
 *                         Write the end result here.
 */
void
compute_master_secret(int ps, int client_random, int server_random, char *master_secret)
{
    printf("Premaster secret: %i%i%i%i\n", ps, client_random, server_random, ps);
    unsigned char *hash = malloc(16 * BYTE_SIZE);
    unsigned char *ps_char = malloc(sizeof(int));
    unsigned char *client_random_char = malloc(sizeof(int));
    unsigned char *server_random_char = malloc(sizeof(int));
    memset(hash, 0, 16);
    memcpy(ps_char, &ps, sizeof(int));
    memcpy(client_random_char, &client_random, sizeof(int));
    memcpy(server_random_char, &server_random, sizeof(int));
    SHA256_CTX *sha_object;
    sha_object = malloc(1*sizeof(SHA256_CTX));
    sha256_init(sha_object);
    sha256_update(sha_object, ps_char, sizeof(int));
    sha256_update(sha_object, client_random_char, sizeof(int));
    sha256_update(sha_object, server_random_char, sizeof(int));
    sha256_update(sha_object, ps_char, sizeof(int));
    sha256_final(sha_object, hash);
    printf("SHA256 RAW OUTPUT:");
    int idx;
    char* hash_array;
    hash_array = malloc(32*BYTE_SIZE);
    for (idx = 0; idx < 16; idx++) {
        sprintf(hash_array+(idx*2), "%02x", hash[idx]);
    }
    printf("hash_ARRAY: %s\n", hash_array);
    memcpy(master_secret, hash_array, 32);
    free(sha_object);
    free(hash);
    free(ps_char);
    free(client_random_char);
    free(server_random_char);
    free(hash_array);
}

/*
 * \brief                  Sends a message to the connected server.
 *                         Returns an error code.
 *
 * \param socketno         A file descriptor for the socket to send
 *                         the message on.
 * \param msg              A pointer to the message to send.
 * \param msg_len          The length of the message in bytes.
 */
int
send_tls_message(int socketno, void *msg, int msg_len)
{
  // YOUR CODE HERE
  ssize_t write_size;
  write_size = write(socketno, msg, msg_len);
  if (write_size != msg_len) {
    return ERR_FAILURE;
  }
  return ERR_OK;
}

/*
 * \brief                  Receieves a message from the connected server.
 *                         Returns an error code.
 *
 * \param socketno         A file descriptor for the socket to receive
 *                         the message on.
 * \param msg              A pointer to where to store the received message.
 * \param msg_len          The length of the message in bytes.
 * \param msg_type         The expected type of the message to receive.
 */
int
receive_tls_message(int socketno, void *msg, int msg_len, int msg_type)
{
  // YOUR CODE HERE
  ssize_t read_size;
  read_size = read(socketno, msg, msg_len);
  if (msg_type != ERROR_MESSAGE) {
    return ERR_FAILURE;
  } else if (read_size != msg_len) {
    return ERR_FAILURE;
  }
  return ERR_OK;
}


/*
 * \brief                Encrypts/decrypts a message using the RSA algorithm.
 *
 * \param result         a field to populate with the result of your RSA calculation.
 * \param message        the message to perform RSA on. (probably a cert in this case)
 * \param e              the encryption key from the key_file passed in through the
 *                       command-line arguments
 * \param n              the modulus for RSA from the modulus_file passed in through
 *                       the command-line arguments
 *
 * Fill in this function with your proj0 solution or see staff solutions.
 */
static void
perform_rsa(mpz_t result, mpz_t message, mpz_t e, mpz_t n)
{

  int odd_num;

  mpz_set_str(result, "1", 10);
  odd_num = mpz_odd_p(e);
  while (mpz_cmp_ui(e, 0) > 0) {
    if (odd_num) {
      mpz_mul(result, result, message);
      mpz_mod(result, result, n);
      mpz_sub_ui(e, e, 1);
    }
    mpz_mul(message, message, message);
    mpz_mod(message, message, n);
    mpz_div_ui(e, e, 2);
    odd_num = mpz_odd_p(e);
  }
}


/* Returns a pseudo-random integer. */
static int
random_int()
{
  srand(time(NULL));
  return rand();
}

/*
 * \brief                 Returns ascii string from a number in mpz_t form.
 *
 * \param output_str      A pointer to the output string.
 * \param input           The number to convert to ascii.
 */
void
mpz_get_ascii(char *output_str, mpz_t input)
{
  int i,j;
  char *result_str;
  result_str = mpz_get_str(NULL, HEX_BASE, input);
  i = 0;
  j = 0;
  while (result_str[i] != '\0') {
    output_str[j] = hex_to_ascii(result_str[i], result_str[i+1]);
    j += 1;
    i += 2;
  }
}

/*
 * \brief                  Returns a pointer to a string containing the
 *                         characters representing the input hex value.
 *
 * \param data             The input hex value.
 * \param data_len         The length of the data in bytes.
 */
char
*hex_to_str(char *data, int data_len)
{
  int i;
  char *output_str = calloc(1+2*data_len, sizeof(char));
  for (i = 0; i < data_len; i += 1) {
    snprintf(output_str+2*i, 3, "%02X", (unsigned int) (data[i] & 0xFF));
  }
  return output_str;
}

/* Return the public key exponent given the decrypted certificate as string. */
void
get_cert_exponent(mpz_t result, char *cert)
{
  char *srch, *srch2;
  char exponent[RSA_MAX_LEN/2];
  memset(exponent, 0, RSA_MAX_LEN/2);
  srch = strchr(cert, '\n');
  srch += 1;
  srch = strchr(srch, '\n');
  srch += 1;
  srch = strchr(srch, '\n');
  srch += 1;
  srch = strchr(srch, ':');
  srch += 2;
  srch2 = strchr(srch, '\n');
  strncpy(exponent, srch, srch2-srch);
  mpz_set_str(result, exponent, 0);
}

/* Return the public key modulus given the decrypted certificate as string. */
void
get_cert_modulus(mpz_t result, char *cert)
{
  char *srch, *srch2;
  char modulus[RSA_MAX_LEN/2];
  memset(modulus, 0, RSA_MAX_LEN/2);
  srch = strchr(cert, '\n');
  srch += 1;
  srch = strchr(srch, '\n');
  srch += 1;
  srch = strchr(srch, ':');
  srch += 2;
  srch2 = strchr(srch, '\n');
  strncpy(modulus, srch, srch2-srch);
  mpz_set_str(result, modulus, 0);
}

/* Prints the usage string for this program and exits. */
static void
usage()
{
    printf("./client -i <server_ip_address> -c <certificate_file> -m <modulus_file> -d <exponent_file>\n");
    exit(1);
}

/* Catches the signal from C-c and closes connection with server. */
static void
kill_handler(int signum)
{
  if (signum == SIGTERM) {
    cleanup();
  }
}

/* Converts the two input hex characters into an ascii char. */
static int
hex_to_ascii(char a, char b)
{
    int high = hex_to_int(a) * 16;
    int low = hex_to_int(b);
    return high + low;
}

/* Converts a hex value into an int. */
static int
hex_to_int(char a)
{
    if (a >= 97) {
	a -= 32;
    }
    int first = a / 16 - 3;
    int second = a % 16;
    int result = first*10 + second;
    if (result > 9) {
	result -= 1;
    }
    return result;
}

/* Closes files and exits the program. */
static void
cleanup()
{
  close(sockfd);
  exit(1);
}
