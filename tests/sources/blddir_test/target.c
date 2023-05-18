#include "target.h"

char* get_target(int name) {
    if (name == 0) {
        return "world";
    }
    return "everyone";
}
