var Alert = ReactBootstrap.Alert;
var Button = ReactBootstrap.Button;
var Checkbox = ReactBootstrap.Checkbox;
var Modal = ReactBootstrap.Modal;

$(function() {
  // Global lists
  var scopeList = [];
  var resourceList = [];
  var authorizationTypeList = [];
  
  // Config variables
  var access_token = "access_token";
  var access_token_expires = 3600;
  
  // tab menu
  $('#nav li a').click(function() {
    $('#nav li').removeClass();
    $(this).parent().addClass('active');
    if (!$(this).parent().hasClass('dropdown'))
      $(".navbar-collapse").collapse('hide');
  });

  // Parse query parameters
  function getQueryParams(qs) {
    qs = qs.split('+').join(' ');

    var params = {},
      tokens,
      re = /[#&]?([^=]+)=([^&]*)/g;

    while (tokens = re.exec(qs)) {
      params[decodeURIComponent(tokens[1])] = decodeURIComponent(tokens[2]);
    }

    return params;
  }
  
  // Get OAuth2 token
  var oauth = {
    access_token: false,
    client_id: "g_admin",
    redirect_uri: "../app/index.html",
    scope: "g_admin"
  }
  
  var currentUser = {loggedIn: false, name: "", email: ""};

  // Function that will be used on every API call
  function APIRequest (method, url, data) {
    return $.ajax({
      method: method,
      url: url,
      data: JSON.stringify(data),
      contentType: data?"application/json; charset=utf-8":null,
      headers: {"Authorization": "Bearer " + oauth.access_token}
    })
    .fail(function (error) {
      if (error.status === 401) {
        oauth.access_token = false;
        currentUser.loggedIn = false;
        ReactDOM.render(
          <LoginComponent user={currentUser} oauth={oauth} />,
          document.getElementById('LoginComponent')
        );
      }
    });
  }

  // Load all lists at startup
  function loadLists () {
    var promises = [
      APIRequest("GET", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/user/"),
      APIRequest("GET", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/client/"),
      APIRequest("GET", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/scope/"),
      APIRequest("GET", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/resource/"),
      APIRequest("GET", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/authorization/")
    ];
    
    $.when(promises)
    .then(function (results) {
      results[0].done(function (result) {
        ReactDOM.render(
          <UserTable users={result} oauth={oauth} />,
          document.getElementById('users')
        );
      });
      
      results[2].done(function (result) {
        scopeList = result;
      });
      
      results[3].done(function (result) {
        resourceList = result;
      });
      
      results[4].done(function (result) {
        authorizationTypeList = result;
        ReactDOM.render(
          <AuthorizationTypeList authTypeList={result} oauth={oauth} />,
          document.getElementById('authType')
        );
      });
    })
    .fail(function (error) {
      if (error.status === 401) {
        currentUser.loggedIn = false;
      }
    });
  }
  
  /**
   * User table management component
   */
  class UserTable extends React.Component {
    constructor(props) {
      super(props);
      var selectedScope = "";
      if (scopeList.length > 0) {
        selectedScope = scopeList[0].name;
      }
      this.state = {
        search: "", 
        offset: 0, 
        limit: 10, 
        users: this.props.users, 
        showModal: false, 
        editUser: { scope: [] }, 
        add: false, 
        userScopeList: [], 
        selectedScope: selectedScope,
        passwordInvalid: false,
        loginInvalid: true,
        showConfirmModal: false,
        messageConfirmModal: "",
        showAlertModal: false,
        messageAlertModal: ""
      };
      
      this.handleSearch = this.handleSearch.bind(this);
      this.handleChangeSearch = this.handleChangeSearch.bind(this);
      this.handleChangeLimit = this.handleChangeLimit.bind(this);
      this.handlePreviousPage = this.handlePreviousPage.bind(this);
      this.handleNextPage = this.handleNextPage.bind(this);
      
      // Modal functions
      this.openModalAdd = this.openModalAdd.bind(this);
      this.closeUserModal = this.closeUserModal.bind(this);
      this.saveUserModal = this.saveUserModal.bind(this);
      this.openModalEdit = this.openModalEdit.bind(this);
      this.handleChangeSource = this.handleChangeSource.bind(this);
      this.handleChangeLogin = this.handleChangeLogin.bind(this);
      this.handleChangeName = this.handleChangeName.bind(this);
      this.handleChangeEmail = this.handleChangeEmail.bind(this);
      this.handleChangePassword = this.handleChangePassword.bind(this);
      this.handleChangeConfirmPassword = this.handleChangeConfirmPassword.bind(this);
      this.handleChangeScopeSelected = this.handleChangeScopeSelected.bind(this);
      this.handleChangeEnabled = this.handleChangeEnabled.bind(this);
      this.addScope = this.addScope.bind(this);
      this.removeScope = this.removeScope.bind(this);
      
      this.openModalDelete = this.openModalDelete.bind(this);
      this.okConfirmModal = this.okConfirmModal.bind(this);
      this.cancelConfirmModal = this.cancelConfirmModal.bind(this);
      
      this.openAlertModal = this.openAlertModal.bind(this);
      this.closeAlertModal = this.closeAlertModal.bind(this);
    }
    
    handleChangeSearch (event) {
      this.setState({search: event.target.value});
    }
    
    handleChangeLimit (event) {
      var limit = parseInt(event.target.value);
      var offset = this.state.offset;
      var search = this.state.search;
      var self = this;
      this.setState(function (prevState) {
        self.runSearch(search, offset, limit);
        return {limit: limit};
      });
    }
    
    handlePreviousPage (event) {
      var limit = this.state.limit;
      var offset = this.state.offset-limit;
      var search = this.state.search;
      var self = this;
      this.setState(function (prevState) {
        self.runSearch(search, offset, limit);
        return {offset: offset};
      });
    }
    
    handleNextPage (event) {
      var limit = this.state.limit;
      var offset = this.state.offset+limit;
      var search = this.state.search;
      var self = this;
      this.setState(function (prevState) {
        self.runSearch(search, offset, limit);
        return {offset: offset};
      });
    }
    
    handleSearch (event) {
      this.runSearch(this.state.search, this.state.offset, this.state.limit);
      event.preventDefault();
    }
    
    // Modal functions
    openModalAdd (event) {
      event.preventDefault();
      this.setState({showModal: true, editUser: {enabled: true,  scope: [], source: "database"}, add: true, userScopeList: [], loginInvalid: true});
    }
    
    openModalEdit (user) {
      var cloneUser = $.extend({}, user);
      this.setState({showModal: true, editUser: cloneUser, add: false, loginInvalid: false});
    }
    
    openModalDelete (user) {
      var message = "Are your sure you want to delete user '" + user.login + "'";
      this.setState({showConfirmModal: true, messageConfirmModal: message, editUser: user});
    }
    
    okConfirmModal (event) {
      event.preventDefault();
      var self = this;
      APIRequest("DELETE", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/user/" + this.state.editUser.login)
      .then(function (result) {
          var users = self.state.users;
          for (var key in users) {
            if (users[key].login === self.state.editUser.login) {
              users.splice(key, 1);
              break;
            }
          };
          self.setState({users: users});
      })
      .done(function (result) {
        self.setState({showConfirmModal: false});
      });
    }
    
    cancelConfirmModal () {
      this.setState({showConfirmModal: false});
    }
    
    openAlertModal (message) {
      this.setState({showAlertModal: true, messageAlertModal: message});
    }
    
    closeAlertModal () {
      this.setState({showAlertModal: false});
    }
    
    closeUserModal(result, value) {
      this.setState({showModal: false});
    }
    
    saveUserModal (event) {
      event.preventDefault();
      var self = this;
      if (this.state.add) {
        APIRequest("GET", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/user/" + self.state.editUser.login)
        .then(function (result) {
          self.openAlertModal("Error, login '" + self.state.editUser.login + "' already exist");
        })
        .fail(function () {
          APIRequest("POST", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/user/", self.state.editUser)
          .then(function (result) {
            var users = self.state.users;
            self.state.editUser.password = "";
            self.state.editUser.confirmPassword = "";
            users.push(self.state.editUser);
            self.setState({users: users});
          })
          .fail(function (error) {
            self.openAlertModal("Error adding user");
          })
          .done(function (result) {
            self.setState({showModal: false});
          });
        })
        
      } else {
        APIRequest("PUT", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/user/" + this.state.editUser.login, this.state.editUser)
        .then(function () {
          var users = self.state.users;
          for (var key in users) {
            if (users[key].login === self.state.editUser.login) {
              users[key] = self.state.editUser;
            }
          };
          self.setState({users: users});
        })
        .done(function (result) {
          self.setState({showModal: false});
        });
      }
    }
    
    handleChangeSource (event) {
      var newUser = $.extend({}, this.state.editUser);
      newUser.source = event.target.value;
      this.setState({editUser: newUser});
    }
    
    handleChangeLogin (event) {
      var isInvalid = !event.target.value;
      var newUser = $.extend({}, this.state.editUser);
      newUser.login = event.target.value || "";
      this.setState({editUser: newUser, loginInvalid: isInvalid});
    }
    
    handleChangeName (event) {
      var newUser = $.extend({}, this.state.editUser);
      newUser.name = event.target.value || "";
      this.setState({editUser: newUser});
    }
    
    handleChangeEmail (event) {
      var newUser = $.extend({}, this.state.editUser);
      newUser.email = event.target.value || "";
      this.setState({editUser: newUser});
    }
    
    handleChangePassword (event) {
      var isInvalid = (!!event.target.value || !!this.state.editUser.confirmPassword) && (event.target.value !== this.state.editUser.confirmPassword || event.target.value.length < 8);
      var newUser = $.extend({}, this.state.editUser);
      newUser.password = event.target.value || "";
      this.setState({editUser: newUser, passwordInvalid: isInvalid});
    }
    
    handleChangeConfirmPassword (event) {
      var isInvalid = (!!this.state.editUser.password || !!event.target.value) && (this.state.editUser.password !== event.target.value || event.target.value.length < 8);
      var newUser = $.extend({}, this.state.editUser);
      newUser.confirmPassword = event.target.value || "";
      this.setState({editUser: newUser, passwordInvalid: isInvalid});
    }
    
    handleChangeScopeSelected (event) {
      this.setState({selectedScope: event.target.value});
    }
    
    removeScope (scope, event) {
      var newUser = $.extend({}, this.state.editUser);
      newUser.scope.splice(newUser.scope.indexOf(scope), 1);
      this.setState({editUser: newUser});
    }
    
    addScope (event) {
      var newUser = $.extend({}, this.state.editUser);
      if (this.state.editUser.scope.indexOf(this.state.selectedScope) == -1) {
        newUser.scope.push(this.state.selectedScope);
        this.setState({editUser: newUser});
      }
    }
    
    handleChangeEnabled (event) {
      var newUser = $.extend({}, this.state.editUser);
      newUser.enabled = !newUser.enabled;
      this.setState({editUser: newUser});
    }
    
    runSearch (search, offset, limit) {
      var self = this;
      if (search) {
        APIRequest("GET", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/user/?search=" + search + "&limit=" + limit + "&offset=" + offset)
        .then(function (result) {
          self.setState({
            users: result
          });
        })
        .fail(function (error) {
          self.openAlertModal("Error while searching users");
        });
      } else {
        APIRequest("GET", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/user/" + "?limit=" + limit + "&offset=" + offset)
        .then(function (result) {
          self.setState({
            users: result
          });
        })
        .fail(function (error) {
          self.openAlertModal("Error while searching users");
        });
      }
    }

    render() {
      var self = this;
      var allScopeList = [];
      scopeList.forEach(function (scope) {
        allScopeList.push(<option value={scope.name} key={scope.name}>{scope.name}</option>)
      });
      var rows = [];
      this.state.users.forEach(function(user) {
        rows.push(
        <tr key={user.login}>
          <td>{user.source}</td>
          <td>{user.login}</td>
          <td>{user.name}</td>
          <td>{user.email}</td>
          <td>{user.scope.join(", ")}</td>
          <td>{user.enabled?"true":"false"}</td>
          <td>
            <div className="input-group">
              <div className="input-group-btn">
                <Button className="btn btn-default" onClick={() => self.openModalEdit(user)}>
                  <i className="glyphicon glyphicon-pencil"></i>
                </Button>
                <Button className="btn btn-default" onClick={() => self.openModalDelete(user)}>
                  <i className="glyphicon glyphicon-trash"></i>
                </Button>
              </div>
            </div>
          </td>
        </tr>);
      });
      var previousOpts = {};
      if (this.state.offset === 0) {
        previousOpts["disabled"] = "disabled";
      }
      var userScopeList = [];
      this.state.editUser.scope.forEach(function (scope) {
        userScopeList.push(
          <span className="tag label label-info" key={scope}>
            <span>{scope}&nbsp;</span>
            <a href="" onClick={(evt) => self.removeScope(scope, evt)}>
              <i className="remove glyphicon glyphicon-remove-sign glyphicon-white"></i>
            </a>
          </span>
        );
      });
      
      return (
        <div>
          <form onSubmit={this.handleSearch}>
            <div className="input-group row">
              <input type="text" className="form-control" placeholder="Search" value={this.state.search} onChange={this.handleChangeSearch}/>
              <div className="input-group-btn">
                <Button className="btn btn-default" onClick={this.handleSearch}>
                  <i className="glyphicon glyphicon-search"></i>
                </Button>
                <Button className="btn btn-default" onClick={this.openModalAdd}>
                  <i className="glyphicon glyphicon-plus"></i>
                </Button>
              </div>
            </div>
          </form>
          <div className="row">
            <div className="col-md-3">
              <div className="input-group">
                <div className="input-group-btn">
                  <button className="btn btn-default" {...previousOpts} type="button" onClick={this.handlePreviousPage}><i className="icon-resize-small fa fa-chevron-left"></i></button>
                </div>
                <div>
                  <select className="form-control" onChange={this.handleChangeLimit} value={this.state.limit}>
                    <option value="10">10</option>
                    <option value="25">25</option>
                    <option value="50">50</option>
                    <option value="100">100</option>
                  </select>
                </div>
                <div className="input-group-btn">
                  <Button className="btn btn-default" type="button" onClick={this.handleNextPage}><i className="icon-resize-small fa fa-chevron-right"></i></Button>
                </div>
              </div>
            </div>
            <div className="col-md-9 text-right">
              <span className="text-center">{this.state.limit} results maximum, starting at result: {this.state.offset}</span>
            </div>
          </div>
          <table className="table table-hover table-responsive">
            <thead>
              <tr>
                <th>Source</th>
                <th>Login</th>
                <th>Name</th>
                <th>E-mail</th>
                <th>Scopes</th>
                <th>Enabled</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {rows}
            </tbody>
          </table>
          <Modal show={this.state.showModal} onHide={this.closeUserModal}>
            <Modal.Header closeButton>
              <Modal.Title>User</Modal.Title>
            </Modal.Header>
            <Modal.Body>
              <div className="row">
                <div className="col-md-6">
                  <label htmlFor="userSource">Source</label>
                </div>
                <div className="col-md-6">
                  <select className="form-control" name="userSource" id="userSource" value={this.state.editUser.source} onChange={this.handleChangeSource}>
                    <option value="ldap">LDAP</option>
                    <option value="database">Database</option>
                  </select>
                </div>
              </div>
              <div className="row">
                <div className="col-md-6">
                  <label htmlFor="userLogin">Login</label>
                </div>
                <div className={this.state.loginInvalid?"col-md-6 has-error":"col-md-6"}>
                  <input className="form-control" type="text" name="userLogin" id="userLogin" disabled={!this.state.add?"disabled":""} placeholder="User Login" value={this.state.editUser.login} onChange={this.handleChangeLogin}></input>
                </div>
              </div>
              <div className="row top-buffer">
                <div className="col-md-6">
                  <label htmlFor="userPassword">Password</label>
                </div>
                <div className={this.state.passwordInvalid?"col-md-6 has-error":"col-md-6"}>
                  <input className="form-control" type="password" name="userPassword" id="userPassword" placeholder="User password" onChange={this.handleChangePassword} value={this.state.editUser.password}></input>
                </div>
              </div>
              <div className="row top-buffer">
                <div className="col-md-6">
                  <label htmlFor="userPasswordConfirm">Confirm password</label>
                </div>
                <div className={this.state.passwordInvalid?"col-md-6 has-error":"col-md-6"}>
                  <input className="form-control" type="password" name="userPasswordConfirm" id="userPasswordConfirm" placeholder="Confirm User password" onChange={this.handleChangeConfirmPassword} value={this.state.editUser.confirmPassword}></input>
                </div>
              </div>
              <div className="row top-buffer">
                <div className="col-md-6">
                  <label htmlFor="userName">Name</label>
                </div>
                <div className="col-md-6">
                  <input className="form-control" type="text" name="userName" id="userName" placeholder="Fullname" value={this.state.editUser.name} onChange={this.handleChangeName}></input>
                </div>
              </div>
              <div className="row top-buffer">
                <div className="col-md-6">
                  <label htmlFor="userEmail">Email</label>
                </div>
                <div className="col-md-6">
                  <input className="form-control" type="text" name="userEmail" id="userEmail" placeholder="User e-mail" value={this.state.editUser.email} onChange={this.handleChangeEmail}></input>
                </div>
              </div>
              <div className="row top-buffer">
                <div className="col-md-6">
                  <label htmlFor="userScope">Scopes</label>
                </div>
                <div className="col-md-6">
                  <div className="input-group">
                    <select id="userScope" name="userScope" className="form-control" value={this.state.scopeSelected} onChange={this.handleChangeScopeSelected}>
                      {allScopeList}
                    </select>
                    <div className="input-group-btn ">
                      <button type="button" name="addScope" id="addScope" className="btn btn-default" onClick={this.addScope}>
                        <i className="icon-resize-small fa fa-plus" aria-hidden="true"></i>
                      </button>
                    </div>
                  </div>
                </div>
              </div>
              <div className="row top-buffer">
                <div className="col-md-6">
                </div>
                <div className="col-md-6" id="userScopeValue">
                {userScopeList}
                </div>
              </div>
              <div className="row top-buffer">
                <div className="col-md-6">
                  <label>Enabled</label>
                </div>
                <div className="col-md-6">
                  <Checkbox validationState="success" checked={this.state.editUser.enabled?"true":null} onChange={this.handleChangeEnabled}></Checkbox>
                </div>
              </div>
            </Modal.Body>
            <Modal.Footer>
              <Button onClick={this.saveUserModal} disabled={this.state.passwordInvalid||this.state.loginInvalid?true:false}>Save</Button>
              <Button onClick={this.closeUserModal}>Cancel</Button>
            </Modal.Footer>
          </Modal>
          <Modal show={this.state.showConfirmModal} onHide={this.cancelConfirmModal}>
            <Modal.Header closeButton>
              <Modal.Title>Delete user</Modal.Title>
            </Modal.Header>
            <Modal.Body>
              {this.state.messageConfirmModal}
            </Modal.Body>
            <Modal.Footer>
              <Button onClick={this.okConfirmModal}>OK</Button>
              <Button onClick={this.cancelConfirmModal}>Cancel</Button>
            </Modal.Footer>
          </Modal>
          <Modal show={this.state.showAlertModal} onHide={this.closeAlertModal}>
            <Modal.Header closeButton>
              <Modal.Title>Users</Modal.Title>
            </Modal.Header>
            <Modal.Body>
              {this.state.messageAlertModal}
            </Modal.Body>
            <Modal.Footer>
              <Button onClick={this.closeAlertModal}>Close</Button>
            </Modal.Footer>
          </Modal>
        </div>
      );
    }
  }

  /**
   * Login/Logout button component
   */
  function LoginInformation (props) {
    return (
      <span>Hello {props.user.name}&nbsp;</span>
    );
  }

  function ConnectMessage (props) {
    return (
      <span>Please log in to the application&nbsp;</span>
    );
  }

  class LogoutButton extends React.Component {
    constructor(props) {
      super(props);

      this.handleLogout = this.handleLogout.bind(this);
    }
    
    render() {
      return (<button type="button" className="btn btn-primary" onClick={this.handleLogout}>
        <i className="fa fa-sign-out" aria-hidden="true"></i>
        &nbsp;Log out
      </button>);
    }
    
    handleLogout() {
      this.props.oauth.access_token = false;
      $.removeCookie(access_token);
      this.props.user.loggedIn = false;
      ReactDOM.render(
        <LoginComponent user={this.props.user} oauth={this.props.oauth} />,
        document.getElementById('LoginComponent')
      );
    }
  }

  class LoginButton extends React.Component {
    constructor(props) {
      super(props);

      this.handleLogin = this.handleLogin.bind(this);
    }
    
    render() {
      return (<button type="button" className="btn btn-primary" onClick={this.handleLogin}>
        <i className="fa fa-sign-in" aria-hidden="true"></i>
        &nbsp;Log in
      </button>);
    }
    
    handleLogin() {
      document.location = "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/auth?response_type=token&client_id="+this.props.oauth.client_id+"&redirect_uri="+this.props.oauth.redirect_uri+"&scope="+this.props.oauth.scope;
    }
  }

  function LoginComponent (props) {
    if (props.user.loggedIn) {
      return (
        <div>
          <LoginInformation user={props.user} oauth={props.oauth} />
          <LogoutButton user={props.user} oauth={props.oauth} />
        </div>
      );
    } else {
      return (
        <div>
          <ConnectMessage />
          <LoginButton oauth={props.oauth} />
        </div>
      );
    }
  }

  /**
   * Authentication type table management component
   */
  class AuthTypeEnableButton extends React.Component {
    constructor(props) {
      super(props);
      this.state = {enabled: this.props.authType.enabled};
      this.handleToggleAuthType = this.handleToggleAuthType.bind(this);
    }
    
    render() {
      if (this.state.enabled) {
        return <button type="button" className="btn btn-danger" onClick={this.handleToggleAuthType} >Disable</button>
      } else {
        return <button type="button" className="btn btn-success" onClick={this.handleToggleAuthType} >Enable</button>
      }
    }
    
    handleToggleAuthType () {
      var self = this;
      APIRequest("PUT","https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/authorization/" + this.props.authType.name, JSON.stringify({description: this.props.authType.description, enabled: !this.state.enabled}))
      .done(function (result) {
        self.setState(prevState => ({
          enabled: !prevState.enabled
        }));
      })
      .fail(function (error) {
        $("#alertTitle").text("Toggle authorization type");
        $("#alertBody").text("Error while changing authorization type");
        $("#alertModal").modal();
      });
    }
  }

  class AuthorizationType extends React.Component {
    constructor(props) {
      super(props);
    }
    
    render () {
      return (
        <tr>
          <td>
            <label>{this.props.authType.name}</label>
          </td>
          <td>
            {this.props.authType.description}
          </td>
          <td>
            <AuthTypeEnableButton authType={this.props.authType} oauth={this.props.oauth} />
          </td>
        </tr>
      );
    }
  }

  function AuthorizationTypeList (props) {
    var rows = [];
    props.authTypeList.forEach(function(authType) {
      rows.push(<AuthorizationType authType={authType} key={authType.name} oauth={props.oauth} />);
    });
    return (
      <div className="well">
        <table className="table table-hover table-responsive">
          <thead>
            <tr>
              <th>Name</th>
              <th>Description</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {rows}
          </tbody>
        </table>
      </div>
    );
  }
  
  /**
   * javscript core code
   */
  var params = getQueryParams(location.hash);

  /**
   * get access_token from url, or from cookie
   */
  if (params.access_token) {
    oauth.access_token = params.access_token;
    var expires = new Date();
    expires.setSeconds(expires.getSeconds() + access_token_expires);
    $.cookie(access_token, params.access_token, {expires: expires});
    document.location = "#";
  } else if ($.cookie(access_token)) {
    oauth.access_token = $.cookie(access_token);
  }

  /**
   * If an acces_token is present, use it to get all lists
   * if no access_token, display the login button
   */
  if (oauth.access_token) {
    APIRequest("GET", "https://hunbaut.babelouest.org/glewlwyddev/glewlwyd/auth/user/")
    .then(function (result) {
      currentUser.loggedIn = true;
      currentUser.name = result.name;
      currentUser.email = result.email;
      loadLists();
    })
    .fail(function (error) {
      if (error.status === 401) {
        currentUser.loggedIn = false;
      }
    })
    .always(function () {
      ReactDOM.render(
        <LoginComponent user={currentUser} oauth={oauth} />,
        document.getElementById('LoginComponent')
      );
    });
  } else {
    ReactDOM.render(
      <LoginComponent user={currentUser} oauth={oauth} />,
      document.getElementById('LoginComponent')
    );
  }
  
});
