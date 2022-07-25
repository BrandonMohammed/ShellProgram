#define _POSIX_C_SOURCE 200112L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <errno.h>

#define TRUE 1
#define FALSE 0

typedef struct {
	int size;
	char **items;
} tokenlist;

struct job{		//background process job
	int jobnum;
	int pidnum;
	char bcmd[256];
};


char *get_input(void);
tokenlist *get_tokens(char *input);

tokenlist *new_tokenlist(void);
void add_token(tokenlist *tokens, char *item);
void free_tokens(tokenlist *tokens);
void overWriteToken(tokenlist *tokens, int index, char* item); //Overwrites tokens->items[index]
//with item
void getPath(char* command, char* buffer);     //will write the path of the command to the buffer.
							// buffer[0] == 0 if command not found.
tokenlist *get_tokens_path(char *input);       //internal function for getPath()
int cmd_execute(tokenlist *tokens);        //executes command, prints error if command not found.
int builtInFunctions(tokenlist* tokens, char** validCommands,
						struct job* jobs, int numofjobs);//executes built in
//functions,
void pushValidCommand(char** validCommands, char* input);   //pushes valid command
void deTokenize(tokenlist* tokens, char* buffer, int startIndex);         //changes token list
//back into string inside buffer
int cmd_execute_c(tokenlist *tokens, char** command);	//executes command, passing char command,
//prints error if command not found.
int o_redirection(tokenlist *tokens, char* file, char** command); //redirects output of command to
//specified file
int b_execute(tokenlist* tokens, struct job jobs[], int numofjobs, int flag, char** command, char
	actual[]);		//executes background processes
int o_redirection_b(tokenlist *tokens, char* file, char** command, struct job jobs[],
	int numofjobs,char actual[]);
int b_execute_c_o(tokenlist *tokens, struct job jobs[], int numofjobs, char** command, int fd,
	char actual[]);
int AsteriskMatch(char* filename, char* echoStr); //checks if echo asterisk string matches a file

int main()
{
	struct job jobs[10];	//array of job structs
	int numofjobs = 0;
	char* validCommands[3];
	for(int i = 0; i < 3; ++i) validCommands[i] = 0;
	while (1) {
		//You do
		//not have to worry about deallocation.
		char* user = getenv("USER");
		char* machine = getenv("MACHINE");
		char* pwd = getenv("PWD");
		printf("%s@%s : %s > ", user, machine, pwd);   //prints proper name and location

		/* input contains the whole command
		 * tokens contains substrings from input split by spaces
		 */

		char *input = get_input();


		if(numofjobs > 0)
		{				  //checks for background processes done
			for(int i =0; i < numofjobs; i++)
			{
				pid_t status = waitpid(jobs[i].pidnum,NULL,WNOHANG);
				if(status != 0)
				{
					printf("[%i][%i]\t %s		DONE\n", jobs[i].jobnum, jobs[i].pidnum,
					jobs[i].bcmd);
					for(int j = i; j<numofjobs; j++)
					{
						jobs[j] = jobs[j+1];
					}
					numofjobs--;
				}
			}
		}

		if (input[0] == 0)
		{
			free(input);
			continue;
		}
		tokenlist *tokens = get_tokens(input);
		char actualInput[256];
		deTokenize(tokens, actualInput, 0);
		int bflag =0;
		int flag = 0;				// i/o redirection and pipe flag (to not execute command twice)
		int cmdValid;						//if a valid command
		int count = 0;					//counts number of pipes in input
		int o_flag = 0;					//if > is followed by < in input
		int i_flag = 0;					//if < is followed by > in input

		if(tokens->items[tokens->size - 1][0] == '&'){ //checks for background &, deletes & and
			//executes
			tokens->items[tokens->size-1] = '\0';
			tokens->size = tokens->size-1;
		//	cmdValid = b_execute(tokens, jobs, numofjobs);	//pass actualInput in for actual var
			bflag=1;
			numofjobs++;
		}

		for (int i = 0; i < tokens->size; i++) {
			if(tokens->items[i][0] == '$')            //finds stuff like $USER and overwrites token
			//with getenv(USER)
			{
				char toEnv[64];
				for (int j = 1; tokens->items[i][j] != 0; ++j)
				{
				    toEnv[j-1] = tokens->items[i][j];
				    toEnv[j] = 0;
				}
				char* fromEnv = getenv(toEnv);
				overWriteToken(tokens, i, fromEnv);
			}
			if(tokens->items[i][0] == '~')                    //tilde expansion
			{
				char* fromEnv = getenv("HOME");
				char restOfStr[256];
				restOfStr[0] = 0;
				for (int j = 1; tokens->items[i][j] != 0; ++j)
				{
					restOfStr[j-1] = tokens->items[i][j];
					restOfStr[j] = 0;
				}
				char mergedStr[256];
				int mergePlace;
				for (mergePlace = 0; fromEnv[mergePlace] != 0; ++mergePlace)
				{
					mergedStr[mergePlace] = fromEnv[mergePlace];
					mergedStr[mergePlace+1] = 0;
				}
				for (int j = 0; restOfStr[j] != 0; ++j)
				{
					mergedStr[mergePlace] = restOfStr[j];
					mergedStr[mergePlace+1] = 0;
					++mergePlace;
				}
				overWriteToken(tokens, i, mergedStr);
			}
			if(tokens->items[i][0] == '>')
			{					//output redirection

				for(int j = 0; j < tokens->size; j++)
				{
					if(tokens->items[j][0] == '<')
					{
						i_flag = 1;							//output redirection detected
					}
				}

				if(i_flag == 0)
				{							//if output redirection only
					if(o_flag == 0)
					{
						int k = i + 1;
						char* file = tokens->items[k];
						flag = 1;

						char* x[tokens->size-1];

						for(int j = 0; j < tokens->size-1; j++)
						{
								x[j] = tokens->items[j];
						}
						x[tokens->size-2] = NULL;
						if(bflag == 1)
						{
							cmdValid = o_redirection_b(tokens, file, x, jobs, numofjobs, 
							actualInput);
						}
						else
						{
							cmdValid = o_redirection(tokens, file, x);
						}
					}
				}
			}

			if(tokens->items[i][0] == '<')
			{								//input redirection
				int o_char = 0;
				char ch;
				int k = i + 1;
				flag = 1;
				int flag2 = 0;					//for command with more than one token (ex: ls -l )
				char* file = tokens->items[k];
				char * command = tokens->items[0];

				for(int j = 1; j < i; j++)
				{
					flag2++;
				}

				for(int j = 0; j < tokens->size; j++)
				{
					if(tokens->items[j][0] == '>')
					{
						o_flag = 1;
						o_char = j;		//position of >
					}
				}

				char *x[4];
				x[0] = command;
				if(flag2 > 0 && i_flag == 0)		//if command more than one token and only input
													//redirection
				{
					x[1] = tokens->items[1];
					x[2] = file;
					x[3] = NULL;
				}
				else if(i_flag == 1 && o_char != 1)		//if both input and output redirection and
														//command
														//is more than one token
				{
					x[1] = tokens->items[1];
					x[2] = file;
					x[3] = NULL;
				}
				else			//normal input redirection or both input and output redirection
								//with one token
								//command
				{
					x[1] = file;
					x[2] = NULL;
					x[3] = NULL;
				}

				if(o_flag != 1){					//normal input redirection (without output
				//redirection)
					if(bflag == 1)								//if background processing
					{
						cmdValid = b_execute(tokens, jobs, numofjobs, flag, x, actualInput);
					}
					else
					{
						cmdValid = cmd_execute_c(tokens, x);
					}
				}
				else{										//both output and input redirection
				//from input
					char *file = tokens->items[o_char + 1];
					if(bflag == 1)								//if background processing
					{
						cmdValid = o_redirection_b(tokens, file, x, jobs, numofjobs, actualInput);
					}
					else
					{
						cmdValid = o_redirection(tokens, file, x);
					}
				}
			}

			if(tokens->items[i][0] == '|')
			{
				flag = 1;

				int temp;
				for (int t = 0; t < tokens->size; t++)
				{
					if(tokens->items[t][0] == '|')
					{
						count++;
						temp = t;				//position of last pipe in command
					}
				}

				if(count <= 2)				//if this is the first iteration of the input
				{
					if(count == 1)   		//one pipe
					{
						int p_fds[2];
						pipe(p_fds);

						char* x1[i];				//command 1
						for(int j = 0; j < i; j++){
							x1[j] = tokens->items[j];
						}
						x1[i]=NULL;

						char buffer1[64];
						getPath(tokens->items[0], buffer1);
						char buffer2[64];
						getPath(tokens->items[i+1], buffer2);

						if (buffer1[0] == 0 || buffer2[0] ==0)
						{
						printf("Command not found.\n");
						cmdValid = 123;
						}
						else
						{
							cmdValid = 0;
							int out;
							out = dup(1);
							int in;
							in = dup(0);
							if (!fork()) 
							{
								dup2(p_fds[1], 1);
								execv(buffer1, x1);
								printf("Error with execv\n");
							}

							dup2(p_fds[0], 0);
							close(p_fds[1]);

							char* x2[tokens->size-i];				//command 2

							for(int j = 0; j < tokens->size-i-1; j++)
							{
								x2[j] = tokens->items[i+j+1];
							}
							x2[tokens->size-i-1]=NULL;

							int pid = fork();
							if(pid == 0)
							{
								execv(buffer2, x2);
								printf("Error with execv\n");
								cmdValid = 123;
							}
							else
							{
								if(bflag == 1)
								{
									pid_t status = waitpid(pid,NULL,WNOHANG);

									if((int)status ==-1)
									{
										printf("error");
									}
									else
									{
										jobs[numofjobs-1].jobnum = numofjobs;
										jobs[numofjobs-1].pidnum = pid;
										strcpy(jobs[numofjobs-1].bcmd, actualInput);
										printf("[%i][%i]\t%s\n", jobs[numofjobs-1].jobnum, 
										jobs[numofjobs-1].pidnum,jobs[numofjobs-1].bcmd);
									}
								}
								else
								{
									waitpid(pid, NULL, 0);
								}
							}
							dup2(out, 1);
							close(out);
							dup2(in, 0);
							close(in);

						}
				}
				else					//two pipes
				{
					int p_fds[2];
					pipe(p_fds);

					char* x1[i];							//command 1
					for(int j = 0; j < i; j++)
					{
						x1[j] = tokens->items[j];
					}
					x1[i]=NULL;

					char buffer1[64];
					getPath(tokens->items[0], buffer1);
					char buffer2[64];
					getPath(tokens->items[i+1], buffer2);
					char buffer3[64];
					getPath(tokens->items[temp + 1], buffer3);

					if (buffer1[0] == 0 || buffer2[0] == 0 || buffer3[0] == 0)
					{
						printf("Command not found.\n");
						cmdValid = 123;
					}
					else
					{
						cmdValid = 0;
						int out;
						out = dup(1);
						int in;
						in = dup(0);
						int pid1 = fork();
						if (pid1 == 0) 
						{
							dup2(p_fds[1], 1);
							execv(buffer1, x1);
							printf("Error with execv\n");
						}
						else
						{
							waitpid(pid1, NULL, 0);
						}

						dup2(p_fds[0], 0);
						close(p_fds[1]);

						int p2_fds[2];
						pipe(p2_fds);

						char* x2[temp - i - 1];			//command 2

						for(int j = 0; j < temp - i - 1; j++)
						{
							x2[j] = tokens->items[i + j + 1];
						}
						x2[temp - i - 1] = NULL;

						int pid = fork();
						if(pid == 0)
						{
							dup2(p2_fds[1], 1);
							execv(buffer2, x2);
							printf("Error with execv\n");
						}
						else
						{
							waitpid(pid, NULL, 0);
						}

						dup2(p2_fds[0], 0);
						close(p2_fds[1]);

						char* x3[tokens->size-i];			//command 3

						for(int j = 0; j < tokens->size-temp-1; j++)
						{
							x3[j] = tokens->items[temp+j+1];
						}
						x3[tokens->size-temp-1]=NULL;

						int pid3 = fork();
						if(pid3 == 0)
						{
							execv(buffer3, x3);
							printf("Error with execv\n");
						}
						else
						{
							waitpid(pid3, NULL, 0);
						}

						dup2(out, 1);
						close(out);
						dup2(in, 0);
						close(in);
					}
				}
 			}
		}

	}
		char* temp[0];
		if(bflag==1 && flag != 1)
		{	//checks for background &, deletes & and executes
			cmdValid = b_execute(tokens, jobs, numofjobs, flag, temp, actualInput);
		}

		free(input);
		int toExCMD = builtInFunctions(tokens, validCommands, jobs, numofjobs);
		if (toExCMD == -1) //exit code
		{
			free_tokens(tokens);
			for (int i = 0; i < 3; ++i) if (validCommands[i] != 0) free(validCommands[i]);
			return 0;
		}
		if (toExCMD == 0)
		{
			if(flag != 1 && bflag==0)
				 cmdValid = cmd_execute(tokens);
			if (cmdValid != 123)
			{
				pushValidCommand(validCommands, actualInput);
			}
		}
		if (toExCMD == 1)
		{
			pushValidCommand(validCommands, actualInput);
		}
		free_tokens(tokens);
	}

	return 0;
}

int AsteriskMatch(char* filename, char* echoStr)
{
	char simpleStr[256];
	int idx = 0;
	for (int i = 0; echoStr[i] != 0; ++i)
	{
		if (!(echoStr[i] == '*' && echoStr[i+1] == '*'))
		{
			simpleStr[idx] = echoStr[i];
			++idx;
			simpleStr[idx] = 0;
		}
	}
	char front = simpleStr[0];
	if (front != '*' && front != filename[0])
	{
		return FALSE;
	}
	char end = simpleStr[idx-2];
	int fdx = 0;
	for (int i = 0; filename[i] != 0; ++i )
	{
		++fdx;
	}
	if (end != '*' && end != filename[fdx-1])
	{
		return FALSE;
	}
	char middle[256];
	int mdx = 0;
	for (int i = 1; i < idx-1; ++i)
	{
		middle[mdx] = simpleStr[i];
		++mdx;
		middle[mdx] = 0;
	}
	int currentIndex = 0;
	int newIndex = 0;
	for (int i = 0; i < mdx; ++i)
	{
		if (middle[i] != '*')
		{
			for (int j = currentIndex; j < fdx; ++j)
			{
				if (filename[j] == middle[i])
				{
					newIndex = j + 1;
					j = fdx;
				}
			}
			if (newIndex - currentIndex == 0)
			{
				return FALSE;
			}
			currentIndex = newIndex;
		}
	}
	return TRUE;
}

void deTokenize(tokenlist* tokens, char* buffer, int startIndex)
{
	buffer[0] = 0;
	for (int i = startIndex; i < tokens->size; i++)
	{
		strcat(buffer, tokens->items[i]);
		strcat(buffer, " \0");
	}
}

void pushValidCommand(char** validCommands, char* input)
{
	char* heapCommand = malloc(256);
	for (int i = 0; input[i] != 0; ++i)
	{
		heapCommand[i] = input[i];
		heapCommand[i+1] = 0;
	}
	if (validCommands[2] != 0) free(validCommands[2]);
	validCommands[2] = validCommands[1];
	validCommands[1] = validCommands[0];
	validCommands[0] = heapCommand;
}


int builtInFunctions(tokenlist* tokens, char** validCommands,
					struct	job* jobs, int numofjobs)
{
	if (!strcmp(tokens->items[0], "exit"))
	{
		if (numofjobs != 0)
		{
			for (int i = 0; i < numofjobs; ++i)
			{
				waitpid(jobs[i].pidnum, 0 , 0);
			}
		}
		int numValid = 0;
		for (int i = 0; i < 3; ++i)
		{
			if (validCommands[i] != 0) ++numValid;
		}
		if (numValid == 0)
		{
			printf("No valid commands were executed in this shell.\n");
		}
		if (numValid == 1)
		{
			printf("The last valid command executed was:\n");
			printf("%s\n", validCommands[0]);
		}
		if (numValid == 2)
		{
			printf("The following was the last two valid commands executed:\n");
			printf("%s\n", validCommands[1]);
			printf("%s\n", validCommands[0]);
		}
		if (numValid == 3)
		{
			printf("The following was the last three valid commands executed:\n");
			printf("%s\n", validCommands[2]);
			printf("%s\n", validCommands[1]);
			printf("%s\n", validCommands[0]);
		}
		return -1;
	}
	if (!strcmp(tokens->items[0], "echo"))
	{
		char output[256];
		deTokenize(tokens, output, 1);
		int quotes = 0;
		int stars = 0;
		for (int i = 0; output[i] != 0; ++i)
		{
			if (output[i] == '\"')
			{
				++quotes;
			}
			if (output[i] == '*')
			{
				++stars;
			}
		}
		if (quotes > 0)
		{
			if (quotes % 2 != 0)
			{
				printf("Unmatched \".");
			}
			else
			{
				for (int i = 0; output[i] != 0; ++i)
				{
					if (output[i] == '\"')
					{
						for (int j = i; output[j] != 0; ++j)
						{
							output[j] = output[j+1];
						}
						--i;
					}
				}
				if (stars > 0)
				{
					int printed = 0;
					char* pwd = getenv("PWD");
					DIR* directory;
					struct dirent* file;
					directory = opendir(pwd);
					if(directory != NULL)
					{
						file = readdir(directory);
						while(file != NULL)
						{
							if(AsteriskMatch(file->d_name, output) == TRUE)
							{
								printf("%s ", file->d_name);
								++printed;
							}
							file = readdir(directory);
						}
					}
					closedir(directory);
					if (printed == 0)
					{
						printf("echo: No match.");
					}
				}
				else
				{
					printf("%s", output);
				}
			}
		}
		else
		{
			if (stars > 0)
			{
				int printed = 0;
				char* pwd = getenv("PWD");
				DIR* directory;
				struct dirent* file;
				directory = opendir(pwd);
				if(directory != NULL)
				{
					file = readdir(directory);
					while(file != NULL)
					{
						if(AsteriskMatch(file->d_name, output) == TRUE)
						{
							printf("%s ", file->d_name);
							++printed;
						}
						file = readdir(directory);
					}
				}
				closedir(directory);
				if (printed == 0)
				{
					printf("echo: No match.");
				}
			}
			else
			{
				printf("%s", output);
			}
		}
		printf("\n");
		return 1;
	}
	if (!strcmp(tokens->items[0], "cd"))
	{
		if (tokens->size == 1)
		{
			char* home = getenv("HOME");
			chdir(home);
		}
		if (tokens->size == 2)
		{
			int err = chdir(tokens->items[1]);
			if (err == -1)
			{
				if (errno == 20)
				{
					printf("Error: target is not a directory.\n");
				}
				if (errno == 2)
				{
					printf("Error: target not found.\n");
				}
				return 1;
			}
		}
		if (tokens->size > 2)
		{
			printf("Error: more than one argument is present.\n");
			return 1;
		}
		char* cwd = getcwd(0,0);
		setenv("PWD", cwd, 1);
		free(cwd);
		return 1;
	}
	if (!strcmp(tokens->items[0], "jobs"))
	{
		for (int i = 0; i < numofjobs; ++i)
		{
			printf("[%i][%i]\t%s\n", jobs[i].jobnum, jobs[i].pidnum,
					jobs[i].bcmd);
		}
		return 1;
	}
	return 0;
}

void getPath(char* command, char* buffer)
{
	DIR* directory;
	struct dirent* file;
	char* PATH = getenv("PATH");
	tokenlist* options = get_tokens_path(PATH);
	for (int i = 0; i < options->size; i++)
	{
		directory = opendir(options->items[i]);
		if(directory != NULL)
		{
			file = readdir(directory);
			while(file != NULL)
			{
				if(!strcmp(command, file->d_name))
				{
					buffer[0] = 0;
					strcat(buffer, options->items[i]);
					strcat(buffer, "/");
					strcat(buffer, command);
					closedir(directory);
					free(options);
					return;
				}
				file = readdir(directory);
			}
		}
	}
	closedir(directory);
	buffer[0] = 0;
	free(options);
}

tokenlist *new_tokenlist(void)
{
	tokenlist *tokens = (tokenlist *) malloc(sizeof(tokenlist));
	tokens->size = 0;
	tokens->items = (char **) malloc(sizeof(char *));
	tokens->items[0] = NULL; /* make NULL terminated */
	return tokens;
}

void overWriteToken(tokenlist *tokens, int index, char* item)
{
    free(tokens->items[index]);
    tokens->items[index] = (char *) malloc(strlen(item) + 1);
    for (int i = 0; item[i] != 0; ++i)
    {
        tokens->items[index][i] = item[i];
        tokens->items[index][i + 1] = 0;
    }
}

void add_token(tokenlist *tokens, char *item)
{
	int i = tokens->size;

	tokens->items = (char **) realloc(tokens->items, (i + 2) * sizeof(char *));
	tokens->items[i] = (char *) malloc(strlen(item) + 1);
	tokens->items[i + 1] = NULL;
	strcpy(tokens->items[i], item);

	tokens->size += 1;
}

char *get_input(void)
{
	char *buffer = NULL;
	int bufsize = 0;

	char line[5];
	while (fgets(line, 5, stdin) != NULL) {
		int addby = 0;
		char *newln = strchr(line, '\n');
		if (newln != NULL)
			addby = newln - line;
		else
			addby = 5 - 1;

		buffer = (char *) realloc(buffer, bufsize + addby);
		memcpy(&buffer[bufsize], line, addby);
		bufsize += addby;

		if (newln != NULL)
			break;
	}

	buffer = (char *) realloc(buffer, bufsize + 1);
	buffer[bufsize] = 0;

	return buffer;
}

tokenlist *get_tokens(char *input)
{
	char *buf = (char *) malloc(strlen(input) + 1);
	strcpy(buf, input);

	tokenlist *tokens = new_tokenlist();

	char *tok = strtok(buf, " ");
	while (tok != NULL) {
		add_token(tokens, tok);
		tok = strtok(NULL, " ");
	}

	free(buf);
	return tokens;
}

tokenlist *get_tokens_path(char *input)
{
	char *buf = (char *) malloc(strlen(input) + 1);
	strcpy(buf, input);

	tokenlist *tokens = new_tokenlist();

	char *tok = strtok(buf, ":");
	while (tok != NULL) {
		add_token(tokens, tok);
		tok = strtok(NULL, ":");
	}

	free(buf);
	return tokens;
}

void free_tokens(tokenlist *tokens)
{
	for (int i = 0; i < tokens->size; i++)
		free(tokens->items[i]);
	free(tokens->items);
	free(tokens);
}

int cmd_execute(tokenlist *tokens)
{
        char buffer[64];
	getPath(tokens->items[0], buffer);
	if (buffer[0] == 0)
	{
		printf("Command not found.\n");
		return 123;
	}
	int pid = fork();
        if(pid == 0)
	{
           	execv(buffer,tokens->items);
		printf("Error with execv");
    	}
        else
	{
	        waitpid(pid,NULL,0);
		return 1;
	}
}

int cmd_execute_c(tokenlist *tokens, char** command)
{
		char buffer[64];
		getPath(tokens->items[0], buffer);
		if (buffer[0] == 0)
		{
			printf("Command not found.\n");
			return 123;
		}
		int pid = fork();
		if(pid == 0)
		{
			execv(buffer,command);
			printf("Error with execv");
		}
		else
		{
			waitpid(pid,NULL,0);
			return 1;
		}
}

int o_redirection(tokenlist *tokens, char* file, char** command)
{
	int valid = 0;					//flag for valid command
	int fd = open(file, O_RDWR | O_CREAT | O_TRUNC);
	int r = chmod( file, S_IRGRP | S_IROTH | S_IRUSR | S_IWGRP | S_IWOTH | S_IWUSR);

	int saved_stdout;
	saved_stdout = dup(1);
	dup2(fd, 1);

	valid = cmd_execute_c(tokens, command);

	dup2(saved_stdout, 1);
	close(saved_stdout);
	return valid;
}

int o_redirection_b(tokenlist *tokens, char* file, char** command, struct job jobs[],
							int numofjobs, char actual[])
{
	int valid = 0;					//flag for valid command
	int fd = open(file, O_RDWR | O_CREAT | O_TRUNC);
	int r = chmod( file, S_IRGRP | S_IROTH | S_IRUSR | S_IWGRP | S_IWOTH | S_IWUSR);

/*	int saved_stdout;
	saved_stdout = dup(1);
	dup2(fd, 1); */

	valid = b_execute_c_o(tokens, jobs, numofjobs, command, fd, actual);

	//dup2(saved_stdout, 1);
	//close(saved_stdout);
	return valid;
}

int b_execute(tokenlist *tokens, struct job jobs[], int numofjobs, int flag, char** command,
									char actual[])
{
	char buffer[64];
	getPath(tokens->items[0], buffer);
	if (buffer[0] == 0)
	{
		printf("Command not found.\n");
		return 123;
	}
	int pid = fork();
	if (pid == 0)
	{
		if (flag == 1)
		{
			execv(buffer, command);
		}
		else
		{
			execv(buffer,tokens->items);
		}
		printf("Error with execv");
	}
	else
	{
		pid_t status = waitpid(pid, NULL, WNOHANG);
		if ( (int)status == -1)
		{
			printf("error");
		}
		else
		{
			jobs[numofjobs-1].jobnum = numofjobs;
			jobs[numofjobs-1].pidnum = pid;
			strcpy(jobs[numofjobs-1].bcmd, actual);
			printf("[%i][%i]\t%s\n", jobs[numofjobs-1].jobnum, jobs[numofjobs-1].pidnum,
			jobs[numofjobs-1].bcmd);
		}
		return 1;
	}
}

int b_execute_c_o(tokenlist *tokens, struct job jobs[], int numofjobs, char** command, int fd,
									char actual[])
{
	char buffer[64];
	getPath(tokens->items[0], buffer);
	if (buffer[0] == 0)
	{
		printf("Command not found.\n");
		return 123;
	}
	int saved_stdout;
	saved_stdout = dup(1);
	dup2(fd, 1);

	int pid = fork();
//	int saved_stdout;
	if(pid == 0)
	{
		execv(buffer,command);
		printf("Error with execv");
	}
	else
	{
		pid_t status = waitpid(pid, NULL, WNOHANG);
		dup2(saved_stdout, 1);
		close(saved_stdout);
		if( (int)status == -1)
		{
			printf("error");
		}
		else
		{
			jobs[numofjobs-1].jobnum = numofjobs;
			jobs[numofjobs-1].pidnum = pid;
			strcpy(jobs[numofjobs-1].bcmd, actual);
			printf("[%i][%i]\t%s\n", jobs[numofjobs-1].jobnum, jobs[numofjobs-1].pidnum,
			jobs[numofjobs-1].bcmd);
		}
		return 1;
	}
}
