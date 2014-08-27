#include <stdint.h>
#include <stdbool.h>

uint32_t MIN_TCOST = 1;
uint32_t MAX_TCOST = 7;
uint32_t TCOST_LOGARITHMIC = true;
uint32_t MIN_MCOST = 7;
uint32_t MAX_MCOST = 13;
uint32_t MCOST_LOGARITHMIC = true;
uint32_t MIN_INLEN = 0;
uint32_t MAX_INLEN = 127;
uint32_t MIN_SALTLEN = 0;
uint32_t MAX_SALTLEN = 127;
uint32_t MIN_OUTLEN = 1;
uint32_t MAX_OUTLEN = 128;

// Only needed if there are invalid t_cost/m_cost combinations.  Increase one or the other
// to make them valid.
void validateCosts(uint32_t *t_cost, uint32_t *m_cost) {
}
