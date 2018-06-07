#include "file_manipulation.h"

char** read_from_file(FILE* f, char** dataFromFile, int* numOfPartsRef, int* SOLP )
{
	long len = 0;
	int remain = 0;
	int numOfFileParts = 0;

	//f = fopen("song_test.mp3", "rb");
	f = fopen("picture_test.jpg", "rb");
	//f = fopen("tekst_test.txt", "rb");

	if (f == NULL)
	{
		printf("No such file found!\n");
		return -1;
	}

	/*searching for end of file*/
	fseek(f, 0, SEEK_END);
	len = ftell(f);
	numOfFileParts = (len / DEFAULT_BUFLEN) + 1;
	remain = len % DEFAULT_BUFLEN;
	dataFromFile = (char**)malloc(numOfFileParts * sizeof(char*));
	*numOfPartsRef = numOfFileParts;
	*SOLP = remain;
	rewind(f);

	for (int i = 0; i < numOfFileParts - 1; i++)
	{
		dataFromFile[i] = (char*)malloc(DEFAULT_BUFLEN * sizeof(char));
		fread(dataFromFile[i], 1, DEFAULT_BUFLEN, f);
	}

	dataFromFile[numOfFileParts - 1] = (char*)malloc((remain) * sizeof(char));
	fread(dataFromFile[numOfFileParts - 1], 1, remain, f);

	fclose(f);
	return dataFromFile;
}

unsigned char* convert_to_char(int number, int* num_size)
{
	unsigned char* numElemInFile;
	int malloc_size = 0;
	if (number >= 1000000)
	{
		malloc_size = 7;
	}
	else if (number >= 100000)
	{
		malloc_size = 6;
	}
	else if (number >= 10000)
	{
		malloc_size = 5;
	}
	else if (number >= 1000)
	{
		malloc_size = 4;
	}
	else if (number >= 100)
	{
		malloc_size = 3;
	}
	else if (number >= 10)
	{
		malloc_size = 2;
	}
	else
	{
		malloc_size = 1;
	}
	numElemInFile = (unsigned char*)malloc(malloc_size+1);
	for (int i = 0; i < malloc_size; i++)
	{
		if (number >= 1000000 && number <= 9999999)
		{
			numElemInFile[i] = (number / 1000000 + '0');
			number %= 1000000;
		}
		else if (number >= 100000 && number < 999999)
		{
			numElemInFile[i] = (number / 100000 + '0');
			number %= 100000;
		}
		else if (number >= 10000 && number < 99999)
		{
			numElemInFile[i] = (number / 10000 + '0');
			number %= 10000;
		}
		else if (number >= 1000 && number < 10000)
		{
			numElemInFile[i] = (number / 1000 + '0');
			number %= 1000;
		}
		else if (number >= 100 && number < 1000)
		{
			numElemInFile[i] = (number / 100 + '0');
			number %= 100;
		}
		else if (number >= 10 && number < 99)
		{
			numElemInFile[i] = (number / 10 + '0');
			number %= 10;
		}
		else
		{
			numElemInFile[i] = number + '0';
		}
	}
	numElemInFile[malloc_size] = 0;
	*num_size = malloc_size + 1;
	return numElemInFile;
}