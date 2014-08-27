#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <getopt.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>

#ifdef __cplusplus
#define EXTERNC extern "C"
#else
#define EXTERNC
#endif

EXTERNC int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen,
    unsigned int t_cost, unsigned int m_cost);

// Simple hack to insure input t_cost and m_cost are valid for the PHS.
void validateCosts(uint32_t *t_cost, uint32_t *m_cost);

// These must be defined in the *-limits file
extern uint32_t MIN_TCOST;
extern uint32_t MAX_TCOST;
extern uint32_t TCOST_LOGARITHMIC;
extern uint32_t MIN_MCOST;
extern uint32_t MAX_MCOST;
extern uint32_t MCOST_LOGARITHMIC;
extern uint32_t MIN_INLEN;
extern uint32_t MAX_INLEN;
extern uint32_t MIN_SALTLEN;
extern uint32_t MAX_SALTLEN;
extern uint32_t MIN_OUTLEN;
extern uint32_t MAX_OUTLEN;

static char *exeName = NULL;

static void usage(const char *format, ...) {
    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, (char *)format, ap);
    va_end(ap);
    fprintf(stderr, "\nUsage: %s [OPTIONS] t_cost m_cost\n"
        "    -D               -- Output binary to stdout for use in dieharder testing, using:\n"
        "                        %s -twocats -d | dieharder -g 200 -a | tee diehard.out\n"
        "    -d num-calls     -- Output text to stdout for use in dieharder testing, using:\n"
        "                        %s -twocats -d > foo; dieharder -g 202 -f foo\n"
        "    -G               -- Generate test vectors for various t_cost/m_cost values\n"
        "    -p password      -- provide a string as the password\n"
        "    -P parallelism   -- How many threads to launch in parallel\n"
        "    -T repeats       -- Output only run time for repeated call\n",
        exeName, exeName, exeName);
    exit(1);
}

static uint32_t readUint32(char flag, char *arg) {
    char *endPtr;
    char *p = arg;
    uint32_t value = strtol(p, &endPtr, 0);
    if(*p == '\0' || *endPtr != '\0') {
        if(flag != '\0') {
            usage("Invalid integer for parameter -%c: %s", flag, arg);
        }
        usage("Invalid integer: %u", arg);
    }
    return value;
}

/* Print a value out in hex - from Catena. */
static void printHex(const char *message, uint8_t *x, uint32_t len) {
    puts(message);
    uint32_t i;
    for(i = 0; i < len; i++) {
        if(i != 0 && i % 8 == 0) {
            puts("");
        }
        printf("%02x ", x[i]);
    }
    printf("     %d (octets)\n\n", len);
}

/* Decode a little-endian length len vector of (unsigned char) into a length
   len/4 vector of (uint32_t).  Assumes len is a multiple of 4. */
static void decodeLittleEndian(uint32_t *dst, const uint8_t *src, uint32_t len) {
    const uint8_t *p = src;
    uint32_t i;
    for(i = 0; i < len / 4; i++) {
        dst[i] = ((uint32_t)(p[0]) + ((uint32_t)(p[1]) << 8) + ((uint32_t)(p[2]) << 16) +
            ((uint32_t)(p[3]) << 24));
        p += 4;
    }
}

/* Encode a length len/4 vector of (uint32_t) into a length len vector of
   (unsigned char) in little-endian form.  Assumes len is a multiple of 4. */
static void encodeLittleEndian(uint8_t *dst, const uint32_t *src, uint32_t len) {
    uint8_t *p = dst;
    uint32_t i;
    for (i = 0; i < len / 4; i++) {
        *p++ = *src;
        *p++ = *src >> 8;
        *p++ = *src >> 16;
        *p++ = *src++ >> 24;
    }
}

static void time_ms(struct timespec *start, struct timespec *end, double *ms)
{
    double start_ms, end_ms;

    start_ms = start->tv_sec * 1000.0 + start->tv_nsec / (1000.0 * 1000);
    end_ms   = end->tv_sec * 1000.0 + end->tv_nsec / (1000.0 * 1000);

    *ms = end_ms - start_ms;
}

// Hack to pass parameters to threads
struct ContextStruct {
    uint32_t repeat;
    uint32_t parallelism;
    void *out;
    size_t outlen;
    const void *in;
    size_t inlen;
    const void *salt;
    size_t saltlen;
    unsigned int t_cost;
    unsigned m_cost;
    double *ms;
};

static void *runPHSThread(void *contextPtr) {
    struct ContextStruct *c = (struct ContextStruct *)contextPtr;
    for(uint32_t i = 0; i < c->repeat; i++) {
        int r = PHS(c->out, c->outlen, c->in, c->inlen, c->salt, c->saltlen, c->t_cost, c->m_cost);
        if (r) {
            printf("Error while hashing: %u\n", r);
            exit(1);
        }
    }
    pthread_exit(NULL);
}

static int time_PHS(uint32_t repeat, uint32_t parallelism, void *out, size_t outlen, const void *in, size_t inlen,
                    const void *salt, size_t saltlen, unsigned int t_cost, unsigned int
                    m_cost, double *ms)
{
    struct timespec start, end;

    if (clock_gettime(CLOCK_MONOTONIC, &start) < 0)
        return -EINVAL;

    struct ContextStruct c;
    c.repeat = repeat;
    c.parallelism = parallelism;
    c.out = out;
    c.outlen = outlen;
    c.in = in;
    c.inlen = inlen;
    c.salt = salt;
    c.saltlen = saltlen;
    c.t_cost = t_cost;
    c.m_cost = m_cost;
    c.ms = ms;

    pthread_t memThreads[parallelism];
    for(uint32_t p = 0; p < parallelism; p++) {
        int rc = pthread_create(&memThreads[p], NULL, runPHSThread, &c);
        if(rc) {
            fprintf(stderr, "Unable to start threads\n");
            return false;
        }
    }
    for(uint32_t p = 0; p < parallelism; p++) {
        (void)pthread_join(memThreads[p], NULL);
    }

    if (clock_gettime(CLOCK_MONOTONIC, &end) < 0)
        return -EINVAL;

    time_ms(&start, &end, ms);

    return 0;
}

// Print the hash value in hex.
static void printCompactHex(const char *message, uint8_t *data, uint8_t len) {
    printf("%s", message);
    for(uint32_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
}

// Print a test vector.
static bool printTest(double maxTime, uint32_t outlen, uint8_t *password, uint32_t passwordSize,
        uint8_t *salt, uint32_t saltSize, uint32_t t_cost, uint32_t m_cost) {
    uint8_t hash[outlen];
    int r;
    double ms;
    if((r = time_PHS(1, 1, hash, outlen, password, passwordSize, salt, saltSize, t_cost, m_cost, &ms))) {
        printf("Password hashing for %s failed with code %d!\n", exeName, r);
        return 1;
    }
    printCompactHex("password:", password, passwordSize);
    printCompactHex(" salt:", salt, saltSize);
    printf(" t_cost:%u m_cost:%u ", t_cost, m_cost);
    printCompactHex("-> ", hash, outlen);
    printf("\n");
    return ms < maxTime;
}

// Print test vectors.
static void printTestVectors(double maxTime) {

    // Generate vectors for password and salt from 0 to 255 for t_cost = 0 .. 7 and m_cost = 0 .. 7
    uint8_t *password = (uint8_t *)"password";
    uint8_t *salt = (uint8_t *)"saltsaltsaltsalt";
    bool tooLong = false;
    for(uint32_t i = 0; i < 256 && !tooLong; i++) {
        uint8_t v = i;
        uint32_t t_cost = MIN_TCOST;
        uint32_t m_cost = MIN_MCOST;
        validateCosts(&t_cost, &m_cost);
        if(MIN_SALTLEN == 0) {
            printTest(maxTime, 32, &v, 1, NULL, 0, t_cost, m_cost);
            printTest(maxTime, 32, NULL, 0, &v, 1, t_cost, m_cost);
            tooLong = !printTest(maxTime, 32, &v, 1, &v, 1, t_cost, m_cost);
        } else {
            tooLong = !printTest(maxTime, 32, &v, 1, salt, MIN_SALTLEN, t_cost, m_cost);
        }
    }

    // Generate vectors for a good range of m_cost and t_cost
    uint32_t t_cost = MIN_TCOST;
    while(t_cost <= MAX_TCOST) {
        tooLong = false;
        uint32_t m_cost = MIN_MCOST;
        validateCosts(&t_cost, &m_cost);
        while(m_cost <= MAX_MCOST && !tooLong) {
            tooLong = !printTest(maxTime, 32, password, 8, salt, 16, t_cost, m_cost);
            if(tooLong && m_cost == MIN_MCOST) {
                return;
            }
            if(tooLong) {
                break;
            }
            if(m_cost == 0) {
                m_cost = 1;
            } else if(MCOST_LOGARITHMIC) {
                m_cost++;
            } else {
                m_cost += 1 + (m_cost >> 1);
            }
            validateCosts(&t_cost, &m_cost);
        }
        if(t_cost == 0) {
            t_cost = 1;
        } else if(TCOST_LOGARITHMIC) {
            t_cost++;
        } else {
            t_cost += 1 + (t_cost >> 1);
        }
        validateCosts(&t_cost, &m_cost);
    }

    // Generate different output lengths
    for(uint32_t i = MIN_OUTLEN; i < MAX_OUTLEN; i++) {
        uint32_t t_cost = MIN_TCOST;
        uint32_t m_cost = MIN_MCOST;
        validateCosts(&t_cost, &m_cost);
        printTest(maxTime, i, password, 8, salt, 16, MIN_TCOST, MIN_MCOST);
    }
}

int main(int argc, char **argv) {
    exeName = argv[0];

    uint8_t out[32];
    char *password = (char *)"password";
    uint32_t passwordlen = 8;
    uint8_t *salt = (uint8_t *)"saltsaltsaltsalt";
    uint32_t numCalls = 1;
    uint32_t outlen = 32;
    uint32_t saltlen = 16;
    uint32_t repeat = 1;
    uint32_t parallelism = 1;
    bool outputDieharderText = false;
    bool outputDieharderBinary = false;
    bool outputTime = false;
    int r;

    char c;
    while((c = getopt(argc, argv, "d:DGp:P:T:")) != -1) {
        switch (c) {
        case 'd':
            outputDieharderText = true;
            numCalls = readUint32(c, optarg);
            break;
        case 'D':
            outputDieharderBinary = true;
            break;
        case 'G':
            printTestVectors(100.0);
            return 0;
        case 'p':
            password = optarg;
            passwordlen = strlen(password);
            break;
        case 'T':
            outputTime = true;
            repeat = readUint32(c, optarg);
            break;
        case 'P':
            parallelism = readUint32(c, optarg);
            break;
        default:
            usage("Invalid argument");
        }
    }

    if(optind + 2 != argc) {
        usage("Invalid number of arguments");
    }
    uint32_t t_cost = readUint32('0', argv[optind]);
    uint32_t m_cost = readUint32('\0', argv[optind+1]);
        
    if(outputDieharderText) {
        printf("type: d\n"
            "count: %u\n"
            "numbit: 32\n", numCalls*8);
    }

    if(outputDieharderText || outputDieharderBinary) {
        uint32_t i;
        for(i = 0; (i < numCalls) || outputDieharderBinary; i++) {
            uint8_t pwdbuf[passwordlen + 4];
            memcpy(pwdbuf, password, passwordlen);
            encodeLittleEndian(pwdbuf + passwordlen, &i, 4);
            if((r = PHS(out, outlen, pwdbuf, passwordlen + 4, salt, saltlen, t_cost, m_cost))) {
                printf("Password hashing for %s failed with code %d!\n", argv[0], r);
                return 1;
            }
            if(outputDieharderText) {
                uint32_t j;
                for(j = 0; j < 8; j++) {
                    uint32_t v;
                    decodeLittleEndian(&v, out + j*4, 4);
                    printf("%u\n", v);
                }
            } else if(outputDieharderBinary) {
                fwrite(out, outlen, 1, stdout);
            } else {
                printHex("", out, outlen);
            }
        }
    } else if (outputTime) {
        double ms;
        if((r = time_PHS(repeat, parallelism, out, outlen, (uint8_t *)password,
                passwordlen, salt, saltlen, t_cost, m_cost, &ms))) {
            printf("Password hashing for %s failed with code %d!\n", argv[0], r);
            return 1;
        }
        printf("Runtime: %2.0f ms\n", ms);
        printHex("", out, outlen);
    } else {
        if((r = PHS(out, outlen, (uint8_t *)password, passwordlen, salt, saltlen, t_cost, m_cost))) {
            printf("Password hashing for %s failed with code %d!\n", argv[0], r);
            return 1;
        }
        printHex("", out, outlen);
    }

    return 0;
}
