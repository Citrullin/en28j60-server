typedef char* (*str_replace_func_pointer)(char *orig, char *rep, char *with);

struct ServerUtils{
    str_replace_func_pointer str_replace;
};

struct ServerUtils* getServerUtils();