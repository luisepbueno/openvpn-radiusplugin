#include "Utils.h"

using namespace std;

/**
 * Split a string into tokens.
 */
const vector<string> tokenize(const string &s, const char &c)
{
    string buff{""};
    vector<string> v;

    for (auto n : s)
    {
        if (n != c)
            buff += n;
        else if (n == c && buff != "")
        {
            v.push_back(buff);
            buff = "";
        }
    }
    if (buff != "")
        v.push_back(buff);

    return v;
}
