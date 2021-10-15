@{
    # Some defaults for all dependencies
    PSDependOptions   = @{
        Target = '.\artifacts\TestSuite'
    }
    'GenericTestSuite'                       = @{
        DependencyType = 'Git'
        Name           = 'https://github.com/matt2005/generictestsuite.git'
    }
}



