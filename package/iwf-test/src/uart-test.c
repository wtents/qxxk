#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <math.h>

#define BAUDRATE B9600
//#define MODEMDEVICE "/dev/term/1"
#define MODEMDEVICE "/dev/ttyS0"
#define _POSIX_SOURCE 1

int main(int argc, char* argv[])
{
//	printf("argc=%d, argv[1]=%s, argv[2]=%s\n",argc,argv[1]);
	int fd, c=0, res, value=0;
	struct termios oldtio, newtio;
	char ch;
	static char str_input[20];
	unsigned char str_output[]={'I','W','F','U','A','R','T','T','E','S','T','\n'};
	
	if (argc!=2 || (strncmp(argv[1],"input",strlen("input"))!=0 && strncmp(argv[1],"output",strlen("output"))!=0)) {
	printf("Usage: uart-test [input / output]\n");
	exit(1);
	}


	/* Open Device and Setup */
	fd = open(MODEMDEVICE, O_RDWR|O_NOCTTY);
	if (fd < 0) {
		perror(MODEMDEVICE);
		exit(1);
	}

	tcgetattr(fd, &oldtio);
	bzero(&newtio, sizeof(newtio));

	newtio.c_cflag = BAUDRATE|CS8|CLOCAL|CREAD;
	newtio.c_iflag = IGNPAR;
	newtio.c_oflag = 0;
	newtio.c_lflag = ICANON;
	newtio.c_cflag &= ~OPOST;

	cfsetispeed(&newtio,BAUDRATE);
	cfsetospeed(&newtio,BAUDRATE);
/*
	newtio.c_cflag |= CS8;
	newtio.c_cflag &= ~PARENB;
	newtio.c_cflag &= ~CSTOPB;
	newtio.c_cflag &= ~CSIZE;
	newtio.c_cflag &= ~CRTSCTS;
	newtio.c_cc[VMIN] = 1;
	newtio.c_cc[VTIME] = 0;
*/

	tcflush(fd, TCIFLUSH);
	tcsetattr(fd, TCSANOW, &newtio);

	if (strncmp(argv[1],"output",strlen("output"))==0) {
		write(fd, str_output, 20);
	}

	if (strncmp(argv[1],"input",strlen("input"))==0) {
		read(fd,str_input,20);
		printf("UART TEST:%s\n",str_input);
	}
	close(fd);
	return 0;
}
