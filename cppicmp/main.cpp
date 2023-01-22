#include "mylib.hpp"

int	main(int argc, char **argv)
{
	if (argc != 4)
	{
		std::cout << "First Arg Source Ip!" << std::endl << "Second Arg Destination Ip!" << std::endl << "Third Arg Data Index!" << std::endl;
		return (0);
	}
	mySock msock;
	msock.createSocket(argv[1], argv[2]);
	msock.setData(argv[3]);
	msock.catchResponse();
	return (0);
}