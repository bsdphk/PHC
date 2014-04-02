#include <stdio.h>

#define N_test 1

/*
 * Assume that only random accesses count towards AT, whereas the sequential
 * writes (and possible read-backs) have zero cost (e.g., through use of
 * external memory that is so cheap its cost is negligible compared to that of
 * our fast RAM, or in the case of TMTO-friendly classic scrypt through the
 * sqrt(N) cores attack).
 */
static double smix1_at(int mode, double N)
{
	switch (mode) {
	case 1:
		return N * N / 3.0;
	case 2:
		return N * N / 2.0;
	}
	return 0;
}

static void print_table(int mode, int steps, double step)
{
	int i;
	double N = N_test;
	double t_norm = 2 * N; /* normalize relative to classic scrypt */
	double base_at = smix1_at(mode, N);
	char *mode_name = "scrypt assuming TMTO is not exploited in 2nd loop";

	switch (mode) {
	case 1:
		mode_name = "pow2";
		break;
	case 2:
		mode_name = "wrap or mod";
		break;
	case 3:
		mode_name = "scrypt assuming TMTO is fully exploited";
	}

#if N_test > 1
	printf("%s\ntrel\tt\tAT\tAT/t\tATnorm\n", mode_name);
#else
	printf("%s\nt\tAT\tAT/t\tATnorm\n", mode_name);
#endif

	for (i = 0; i < steps; i++) {
		double t2rel = i * step;
		double t2 = t2rel * N;
		double t = N + t2;
		double at = base_at + t2 * N / (mode == 3 ? 2.0 : 1.0);
		double at_per_time = at / t;
		double N_norm = N * t_norm / t;
		double t2_norm = t2rel * N_norm;
		double base_at_norm = smix1_at(mode, N_norm);
		double at_norm = base_at_norm + t2_norm * N_norm;

#if N_test > 1
		printf("%.2f\t%.2f\t%.3f\t%.3f\t%.3f\n",
		    1 + t2rel, t, at, at_per_time, at_norm);
#else
		printf("%.2f\t%.2f\t%.3f\t%.3f\n",
		    t, at, at_per_time, at_norm);
#endif
	}
}

int main(void)
{
	print_table(0, 111, 0.01);
	print_table(1, 111, 0.01);
	print_table(2, 111, 0.01);
	print_table(3, 111, 0.01);
	return 0;
}
