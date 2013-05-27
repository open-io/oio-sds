%{
#include <glib.h>
#include "./eventhandler_internals.h"
#include "./cfg.yacc.h"
#if 1
# define T do { g_printerr("%s:%d [%s]\n",__FILE__,__LINE__,yytext) ; } while(0)
#else
# define T
#endif
%}
%option reentrant bison-bridge
%option noyywrap
%option nounput
%%
[#].*[\n]                     { T; }
[ \t\r\n]+                    { T; }
["][^"]*["]                   { T; yylval->s=g_strdup(yytext+1); yylval->s[strlen(yylval->s)-1]='\0' ; return PATTERN_TK; }
[Dd][Rr][Oo][Pp]              { T; return DROP_TK; }
[Ee][Xx][Ii][Tt]              { T; return EXIT_TK; }
[Aa][Dd][Dd][Rr][Ee][Ss][Ss]  { T; return ADDRESS_TK; }
[Ss][Ee][Rr][Vv][Ii][Cc][Ee]  { T; return SERVICE_TK; }
[.]             { T; return DOT_TK; }
[;]             { T; return SEMICOLON_TK; }
[:]             { T; return COLON_TK; }
[,]             { T; return COMA_TK; }
[0-9]+                        { T; yylval->i=g_ascii_strtoll(yytext,NULL,10) ; return NUM_TK; }
[.-_0-9A-Za-z?*]+             { T; yylval->s=g_strdup(yytext) ; return PATTERN_TK; }
.               { T; }
%%

