void fun1()
{
    int quux = 1;
}

void fun2()
{
    int qux = 1;
    fun1();
}

void fun3()
{
    int baz = 1;
    fun2();
}

void fun4()
{
    int bar = 1;
    fun3();
}

void fun5()
{
    int foo = 1;
    fun4();
}

int main()
{
    fun5();
}