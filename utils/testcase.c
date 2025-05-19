#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

int i = 1;
short s = 123;
long l = 13134243432;
char *str = "global string";

int set_var(int i_l, short s_l, long l_l) {
    i = i_l;
    s = s_l;
    l = l_l;
    return 0;
}

void func_1(){
    int i_l = 1;
    short s_l = 123;
    long l_l = 13134243432;
    char *str_l = "local string";
    char *str_l_alt = "another local string";

    i_l = 1;
    goto label_last;

label_while:{
    while(i_l == 1){
        s_l = 321;
        i_l++;
        }
    }
  
label_if:{
    if(s_l == 123){
        s_l--;
        l_l++;
        }
    }  

label_switch:{
    switch(i_l){
        case 0:
            i_l = 15;
            break;
        case 1:
            s_l = 456;
            break;
        case 2:
            str_l = str_l_alt;
            break;
        default:
            l_l = 9876543;
            break;
        }
    }
    
label_for:{
    for (int loop = 0; loop < 111; loop++){
        l_l = 13134243433;
        }
    }

label_none:{
    set_var(i_l, s_l, l_l);
    str = str_l;
    printf("%s", str);
    return;
    }

label_last:{  
    goto label_while;
    }
}

int main(){
    func_1();
    return 0;
}
