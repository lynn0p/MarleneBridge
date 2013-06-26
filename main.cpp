#include <QtCore>
#include <iostream>
#include "task.h"

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    Task *task = new Task(&a);
    QTimer::singleShot(0, task, SLOT(run()));
    return a.exec();
}
