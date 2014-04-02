#ifndef TURTLE_H
#define TURTLE_H

unsigned char * turtle(unsigned char * res,
 const unsigned char * X, const unsigned int sz, const unsigned int w,
 unsigned char * (*f)(const unsigned int, unsigned char *, const unsigned char *,
                        const unsigned int, const unsigned char *, const unsigned int),
 unsigned char * f_data, const unsigned int f_data_size);

unsigned char * turtle_inplace(
 unsigned char * X, const unsigned int sz, const unsigned int w,
 unsigned char * (*f)(const unsigned int, unsigned char *, const unsigned char *,
                        const unsigned int, const unsigned char *, const unsigned int),
 unsigned char * f_data, const unsigned int f_data_size);

#endif
