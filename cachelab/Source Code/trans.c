/* 
 * trans.c - Matrix transpose B = A^T
 *
 * Each transpose function must have a prototype of the form:
 * void trans(int M, int N, int A[N][M], int B[M][N]);
 *
 * A transpose function is evaluated by counting the number of misses
 * on a 1KB direct mapped cache with a block size of 32 bytes.
 */ 
#include <stdio.h>
#include "cachelab.h"

int is_transpose(int M, int N, int A[N][M], int B[M][N]);

/* 
 * transpose_submit - This is the solution transpose function that you
 *     will be graded on for Part B of the assignment. Do not change
 *     the description string "Transpose submission", as the driver
 *     searches for that string to identify the transpose function to
 *     be graded. 
 */
char transpose_submit_desc[] = "Transpose submission";
void transpose_submit(int M, int N, int A[N][M], int B[M][N])
{
    /* cache overview: s = 5, E = 1, b = 5 
     * so total 32 byte = 8 int can be stored in a block
     * total 32 blocks
     */
    if (M == 32)
    {
        int i, j, k;
        int t0, t1, t2, t3, t4, t5, t6, t7;
        for (i = 0; i < N; i += 8)
        {
            for (j = 0; j < M; j += 8)
            {
                for (k = i; k < i + 8; k++)
                {
                    t0 = A[k][j];
                    t1 = A[k][j + 1];
                    t2 = A[k][j + 2];
                    t3 = A[k][j + 3];
                    t4 = A[k][j + 4];
                    t5 = A[k][j + 5];
                    t6 = A[k][j + 6];
                    t7 = A[k][j + 7];

                    B[j][k] = t0;
                    B[j + 1][k] = t1;
                    B[j + 2][k] = t2;
                    B[j + 3][k] = t3;
                    B[j + 4][k] = t4;
                    B[j + 5][k] = t5;
                    B[j + 6][k] = t6;
                    B[j + 7][k] = t7;
                }
            }
        }
    }

    if (M == 64)
    {
        int i, j, k, l;
        int t0, t1, t2, t3, t4, t5, t6, t7;
        for (i = 0; i < N; i += 8)
        {
            for (j = 0; j < M; j += 8)
            {
                for (k = i; k < i + 4; ++k)
                {
                    /* read upper left, upper right*/
                    t0 = A[k][j];
                    t1 = A[k][j+1];
                    t2 = A[k][j+2];
                    t3 = A[k][j+3];
                    t4 = A[k][j+4];
                    t5 = A[k][j+5];
                    t6 = A[k][j+6];
                    t7 = A[k][j+7];

                    B[j][k] = t0;
                    B[j+1][k] = t1;
                    B[j+2][k] = t2;
                    B[j+3][k] = t3;
                    /* reverse the sequence */
                    B[j][k+4] = t7;
                    B[j+1][k+4] = t6;
                    B[j+2][k+4] = t5;
                    B[j+3][k+4] = t4;
                }
                for (l = 0; l < 4; ++l)
                {
                   /* read by column */
                    t0 = A[i+4][j+3-l];
                    t1 = A[i+5][j+3-l];
                    t2 = A[i+6][j+3-l];
                    t3 = A[i+7][j+3-l];
                    t4 = A[i+4][j+4+l];
                    t5 = A[i+5][j+4+l];
                    t6 = A[i+6][j+4+l];
                    t7 = A[i+7][j+4+l];

                   /* transfer upper right to lower left */
                    B[j+4+l][i] = B[j+3-l][i+4];
                    B[j+4+l][i+1] = B[j+3-l][i+5];
                    B[j+4+l][i+2] = B[j+3-l][i+6];
                    B[j+4+l][i+3] = B[j+3-l][i+7];
                   /* place the lower blocks to right */
                    B[j+3-l][i+4] = t0;
                    B[j+3-l][i+5] = t1;
                    B[j+3-l][i+6] = t2;
                    B[j+3-l][i+7] = t3;
                    B[j+4+l][i+4] = t4;
                    B[j+4+l][i+5] = t5;
                    B[j+4+l][i+6] = t6;
                    B[j+4+l][i+7] = t7;
                }
            }
        }
    }

    if (M == 61)
    {
        int i, j, k, l;
        for (i = 0; i < N; i += 16)
        {
            for (j = 0; j < M; j += 16)
            {
                for (k = i; k < i + 16 && k < N; k++)
                {
                    for (l = j; l < j + 16 && l < M; l++)
                    {
                        B[l][k] = A[k][l];
                    }
                }
            }
        }
    }
}

/* 
 * You can define additional transpose functions below. We've defined
 * a simple one below to help you get started. 
 */ 

/* 
 * trans - A simple baseline transpose function, not optimized for the cache.
 */
char trans_desc[] = "Simple row-wise scan transpose";
void trans(int M, int N, int A[N][M], int B[M][N])
{
    int i, j, tmp;

    for (i = 0; i < N; i++) {
        for (j = 0; j < M; j++) {
            tmp = A[i][j];
            B[j][i] = tmp;
        }
    }    

}

/*
 * registerFunctions - This function registers your transpose
 *     functions with the driver.  At runtime, the driver will
 *     evaluate each of the registered functions and summarize their
 *     performance. This is a handy way to experiment with different
 *     transpose strategies.
 */
void registerFunctions()
{
    /* Register your solution function */
    registerTransFunction(transpose_submit, transpose_submit_desc); 

    /* Register any additional transpose functions */
    registerTransFunction(trans, trans_desc); 

}

/* 
 * is_transpose - This helper function checks if B is the transpose of
 *     A. You can check the correctness of your transpose by calling
 *     it before returning from the transpose function.
 */
int is_transpose(int M, int N, int A[N][M], int B[M][N])
{
    int i, j;

    for (i = 0; i < N; i++) {
        for (j = 0; j < M; ++j) {
            if (A[i][j] != B[j][i]) {
                return 0;
            }
        }
    }
    return 1;
}

