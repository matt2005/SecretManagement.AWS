@{
    # Some defaults for all dependencies
    PSDependOptions                      = @{
        Target = '.\artifacts\dependencies'
        AddToPath = $True
    }
  'AWS.Tools.Common' = @{
        DependencyType = 'PSGalleryModule'
        Parameters     = @{
            Repository = 'PSGallery'
        }
    }
  'AWS.Tools.SecurityToken' = @{
        DependencyType = 'PSGalleryModule'
        Parameters     = @{
            Repository = 'PSGallery'
        }
    }
}






