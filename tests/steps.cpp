void fun1()
{
    int foo = 1;
}

void fun2()
{
    int foo = 1;
    fun1();
}

void fun3()
{
    int foo = 1;
    fun2();
}

void fun4()
{
    int foo = 1;
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