#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <zeditty.h>
#include <unistd.h>
#include <sys/syscall.h>
uint16_t *CALL_TABLE;
uint16_t CALL_TABLE_SIZE;
uint16_t CALL_ARGV;
uint16_t CALL_ARGC;
void ports_out(z_Machine *mm, unsigned char port, unsigned char value)
{
	switch (port)
	{
		case 0:
			unsigned short argc;
			unsigned short addr;
			z_GetReg(mm, z_REG_HL, &argc);
			z_GetReg(mm, z_REG_DE, &addr);
			uint64_t argv[7];
			for (int i = 0; i < 8; i++)
			{
				if (i >= argc)
					argv[i] = 0;
				else
					z_ReadData(mm, addr + i * sizeof(uint64_t), (unsigned char*)(argv + i), sizeof(uint64_t));
			}
			//we have to offset certain arguments if they're related to memory addressing
			for (int i = 0; i < CALL_TABLE_SIZE; i += 2)
			{
				if (CALL_TABLE[i] == argv[0])
				{
					for (int j = 1; j < argc; j++)
					{
						if ( (CALL_TABLE[i + 1] >> (j - 1))&1 )
						{
							argv[j] += (uint64_t)mm->MEM;
						}
					}
					break;
				}
			}
			syscall(argv[0], argv[1], argv[2], argv[3], argv[4], argv[5], argv[6]);
		break;
		case 0x01: putchar(value); break;
		case 0xFF: z_Stop(mm); break;
		default:
			fprintf(stderr, "Invalid port write (%i;%i).\n", port, value);
	}
}

unsigned char ports_in(z_Machine *mm, unsigned char port)
{
	switch (port)
	{
		case 0x01: return getchar();
		case 0x02: return CALL_ARGC;
		case 0x03: return CALL_ARGV >> 8;
		case 0x04: return CALL_ARGV;
		default:
			fprintf(stderr, "Invalid port read (%i).\n", port);
	}
	return 0;
}

int load_table()
{
	FILE *f = fopen("/usr/share/zedexconf", "r");
	if (!f)
	{
		return 0;
	}
	int p = 0;
	int n = 0;
	int c;
	int b = 1;
	int s = 0;
	int a = 0;
	CALL_TABLE = malloc(0);
	CALL_TABLE_SIZE = 0;
	while ( (c = fgetc(f)) != EOF )
	{
		if (c == '\n')
		{
			a |= 1 << (n - 1);
			CALL_TABLE = realloc(CALL_TABLE, sizeof(uint16_t) * (CALL_TABLE_SIZE + 2));
			CALL_TABLE[CALL_TABLE_SIZE + 0] = s;
			CALL_TABLE[CALL_TABLE_SIZE + 1] = a;
			CALL_TABLE_SIZE += 2;
			b = 1;
			n = 0;
			a = 0;
		}
		else if (c == ' ')
		{
			if (b) s = n;
			else a |= 1 << (n - 1);
			p++;
			n = 0;
			b = 0;
		}
		else
		{
			n *= 10;
			n += (c - '0');
		}
	}
	fclose(f);
	return 1;
}

int main(int argc, char **argv)
{
	if (!load_table())
	{
		printf("This software required a configuration\n");
		printf("file stored at `/usr/share/regexconf`.\n");
		return 1;
	}

	if (argc < 2)
	{
		fprintf(stderr, "Usage: %s [file]\n", argv[0]);
		exit(1);
	}

	//Setup our virtual machine
	z_Machine mm;
	z_InitMachine(&mm);
	mm.PortOutCallback = ports_out;
	mm.PortInCallback = ports_in;

	//Load our program
	FILE *f = fopen(argv[1], "r");
	if (!f)
	{
		fprintf(stderr, "File `%s` not found.\n", argv[1]);
		exit(1);
	}
	for (int c, i = 0; (c = fgetc(f)) != EOF; i++)
	{
		unsigned char b = (unsigned char)c;
		z_WriteData(&mm, i, &b, 1);
	}
	fclose(f);

	//load argument data
	uint16_t argtab[256];
	uint8_t argtabL = 0;
	size_t argl = 0;

	uint16_t argstart = 3;
	uint16_t argend = argstart + 128;

	uint16_t pos = argend;
	for (int i = 1; i < (argc > 64 ? 64 : argc); i++)
	{
		int l = strlen(argv[i]) + 1;
		int estaddr = pos - (l + (argtabL + 1) * sizeof(uint16_t));
		if ( estaddr < argstart )
		{
			break;
		}

		pos -= l;
		z_WriteData(&mm, pos, argv[i], l);
		argtab[argtabL++] = pos;
	}
	pos -= argtabL * sizeof(uint16_t);
	CALL_ARGV = pos;
	CALL_ARGC = argtabL;
	for (int i = 0; i < argtabL; i++)
	{
		unsigned char u = argtab[i] >> 8;
		unsigned char l = argtab[i] & 0xFF;
		z_WriteData(&mm, pos++, &l, 1);
		z_WriteData(&mm, pos++, &u, 1);
	}

	//Run the program
	z_Run(&mm, 0x0000);

	free(CALL_TABLE);
	return 0;
}
