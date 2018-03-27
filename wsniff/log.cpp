#include <time.h>
#include <fstream>
#include <stdarg.h>
#include "log.h"

using namespace std;

char* buf = new char[65000];
string mformat(const char *fmt, ...)
{
	//size_t size = 65000;
	//char* buf = new char[65000];
	/*while (1)
	{*/
		va_list args;
		int n;

		va_start(args, fmt);
		n = vsprintf(buf, fmt, args);
		va_end(args);

		std::string s(buf);
		return s;
		/*if ((n > -1) && (static_cast<size_t>(n) < size))
		{
			std::string s(buf);
			return s;
		}*/
		// Else try again with more space.  
		/*size = size * 2 >= 65535 
			? 65534
			: size * 2 ;*/

	//}

}

char *Date = new char[16],
	 *Time = new char[20],
	 *LOG_TYPE = new char[10],
	 *outlog = new char[65000],
	 *FilePath = new char[40];
struct tm *p;
char* timestamp = new char[7];
void LOGS(int type, int wrap, string msg)
{

	//CString Date, Time, LOG_TYPE, log, FilePath;
	/*char *Date = new char[16], 
		 *Time = new char[20], 
		 *LOG_TYPE = new char[10],
		 *log = new char[65000],
		 *FilePath = new char[40];*/
	
	char *wday[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
	time_t timep;
	time(&timep); /*获得time_t结构的时间，UTC时间*/
	p = localtime(&timep); /*转换为struct tm结构的UTC时间*/

	sprintf(Date, "%d-%02d-%02d", 1900 + p->tm_year, 1 + p->tm_mon, p->tm_mday);
	sprintf(Time, "%s %02d:%02d:%02d", wday[p->tm_wday], p->tm_hour, p->tm_min, p->tm_sec);

	switch (type)
	{
	case 0:
		LOG_TYPE = "[INFO] ";
		break;
	case 1:
		LOG_TYPE = "[WARN] ";
		break;
	case 2:
		LOG_TYPE = "[ERROR]";
		break;
	case 3:
		LOG_TYPE = "[DEBUG]";
		break;
	default:
		LOG_TYPE = "[INFO] ";
		break;
	}
	
	sprintf(outlog, "%s%s%s %s  %s\n", (wrap == 0 ? "" : "\n"), LOG_TYPE, Date, Time, msg.c_str());

	cout << outlog;

	sprintf(FilePath, "../logs/log_%s_%s.txt", Date, timestamp);

	ofstream SaveFile(FilePath, ios::app);
	if (!SaveFile)
	{
		cout << "Can't open the file!" << endl;
	}
	SaveFile << outlog;
	SaveFile.close();

	/*delete[] Date, Time, LOG_TYPE, log, FilePath;
	Date = nullptr;
	Time = nullptr;
	LOG_TYPE = nullptr;
	log = nullptr;
	FilePath = nullptr;*/
	return;
}

void getTimestamp()
{
	time_t timep;
	time(&timep); /*获得time_t结构的时间，UTC时间*/
	struct tm *t;
	t = localtime(&timep); /*转换为struct tm结构的UTC时间*/
	sprintf(timestamp, "%02d%02d%02d", t->tm_hour, t->tm_min, t->tm_sec);
	return;
}