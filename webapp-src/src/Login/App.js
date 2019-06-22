import React, { Component } from 'react';

import apiManager from '../lib/APIManager';
import messageDispatcher from '../lib/MessageDispatcher';
import Notification from '../lib/Notification';
import Buttons from './Buttons';
import Body from './Body';
import PasswordForm from './PasswordForm';
import NoPasswordForm from './NoPasswordForm';

class App extends Component {
  constructor(props) {
    super(props);
    this.state = {
      newUser: false,
      newUserScheme: props.scheme,
      userList: [],
      currentUser: false,
      config: props.config,
      loaded: false,
      lang: i18next.language,
      scope: [],
      scheme: false,
      client: false,
      showGrant: true,
      showGrantAsterisk: false,
    };

    this.initProfile = this.initProfile.bind(this);
    this.checkClientScope = this.checkClientScope.bind(this);
    this.checkScopeScheme = this.checkScopeScheme.bind(this);
    this.changeLang = this.changeLang.bind(this);

    if (this.state.config) {
      this.initProfile();
    }
    
    messageDispatcher.subscribe('App', (message) => {
      if (message.type === "InitProfile") {
        this.initProfile();
      } else if (message.type === "NewUser") {
        this.setState({newUser: true});
      } else if (message.type === "ToggleGrant") {
        this.setState({showGrant: !this.state.showGrant});
      } else if (message.type === "newUserScheme") {
        this.setState({newUserScheme: message.scheme});
      }
    });
  }

  initProfile() {
    apiManager.glewlwydRequest("/profile_list")
    .then((res) => {
      var newState = {};
      if (res.length) {
        newState.currentUser = res[0];
      }
      newState.newUser = false;
      newState.userList = res;
      newState.loaded = true;
      this.setState(newState, () => {
        if (this.state.config.params.scope) {
          this.checkClientScope(this.state.config.params.client_id||false, this.state.config.params.scope);
        } else if (this.state.config.params.scope) {
          this.checkScopeScheme(this.state.config.params.scope);
        } else {
          this.setState({showGrant: false, showGrantAsterisk: false});
        }
      });
    })
    .fail((error) => {
      if (error.status != 401) {
        messageDispatcher.sendMessage('Notification', {type: "warning", message: i18next.t("error-api-connect")});
      }
      this.setState({newUser: true, currentUser: false, userList: [], loaded: true});
    });
  }

  checkClientScope(clientId, scopeList) {
    if (clientId) {
      apiManager.glewlwydRequest("/auth/grant/" + encodeURI(clientId) + "/" + encodeURI(scopeList))
      .then((res) => {
        var scopeGranted = [];
        var scopeGrantedDetails = {};
        var showGrant = true;
        var showGrantAsterisk = false;
        res.scope.forEach((scope) => {
          if (scope.granted) {
            showGrant = false;
            scopeGranted.push(scope.name);
            scopeGrantedDetails[scope.name] = scope;
          } else {
            showGrantAsterisk = true;
          }
        });
        apiManager.glewlwydRequest("/auth/scheme/?scope=" + encodeURI(scopeGranted.join(" ")))
        .then((schemeRes) => {
          this.setState({client: res.client, scope: res.scope, scheme: schemeRes, showGrant: showGrant, showGrantAsterisk: showGrantAsterisk}, () => {
            if (showGrant) {
              this.setState({client: res.client, scope: res.scope, showGrant: showGrant, showGrantAsterisk: showGrantAsterisk});
            }
          });
        })
        .fail((error) => {
          messageDispatcher.sendMessage('Notification', {type: "warning", message: i18next.t("login.error-scheme-scope-api")});
        });
      })
      .fail((error) => {
        messageDispatcher.sendMessage('Notification', {type: "warning", message: i18next.t("login.error-grant-api")});
      });
    }
  }
  
  checkScopeScheme(scopeList) {
    apiManager.glewlwydRequest("/auth/scheme/?scope=" + scopeList)
    .then((schemeRes) => {
      this.setState({scope: scopeList.split(" "), scheme: schemeRes, showGrant: false, showGrantAsterisk: false});
    })
    .fail((error) => {
      messageDispatcher.sendMessage('Notification', {type: "warning", message: i18next.t("login.error-scheme-scope-api")});
    });
  }

  changeLang(e, lang) {
    i18next.changeLanguage(lang)
    .then(() => {
      this.setState({lang: lang});
    });
  }

	render() {
    if (this.state.config) {
      for (var scope in this.state.scheme) {
        var curScope = this.state.scheme[scope];
        if (curScope.isAuth) {
          scopeList.push(
          <li className="list-group-item" key={"scope-"+iScope}>
            <h3><span className="badge badge-success">{curScope.display_name}</span></h3>
          </li>
          );
        } else {
          var groupList = [];
          var iGroup = 0;
          for (var group in curScope.schemes) {
            var schemeList = [];
            curScope.schemes[group].forEach((scheme, index) => {
              if (scheme.scheme_authenticated) {
                schemeList.push(<li className="list-group-item" key={"scheme-"+index}><span className="badge badge-success">{scheme.scheme_display_name}</span></li>);
              } else {
                schemeList.push(<li className="list-group-item" key={"scheme-"+index}><a className="badge badge-primary" href="#" onClick={(e) => this.handleSelectScheme(e, scheme)}>{scheme.scheme_display_name}</a></li>);
              }
            });
            groupList.push(<li className="list-inline-item" key={"group-"+iGroup}>
              <ul className="list-group">
                {schemeList}
              </ul>
            </li>);
            iGroup++;
          }
          scopeList.push(
            <li className="list-group-item" key={"scope-"+iScope}>
              <h3><span className="badge badge-secondary">{i18next.t("login.scheme-list-scope", {scope:curScope.display_name})}</span></h3>
              <ul className="list-inline">
                {groupList}
              </ul>
            </li>
          );
        }
        iScope++;
      }

      var body = "";
      if (this.state.loaded) {
        if (this.state.newUser) {
          if (!this.state.newUserScheme) {
            body = <PasswordForm config={this.state.config} callbackInitProfile={this.initProfile}/>;
          } else {
            body = <NoPasswordForm config={this.state.config} callbackInitProfile={this.initProfile} scheme={this.state.newUserScheme}/>;
          }
        } else {
          body = <Body config={this.state.config} currentUser={this.state.currentUser} client={this.state.client} scope={this.state.scope} scheme={this.state.scheme} showGrant={this.state.showGrant}/>;
        }
      }
      var langList = [];
      ["en","fr"].forEach((lang, i) => {
        if (lang === i18next.language) {
          langList.push(<a className="dropdown-item active" href="#" key={i}>{lang}</a>);
        } else {
          langList.push(<a className="dropdown-item" href="#" onClick={(e) => this.changeLang(e, lang)} key={i}>{lang}</a>);
        }
      });
      return (
        <div aria-live="polite" aria-atomic="true" style={{position: "relative", minHeight: "200px"}}>
          <div className="card center" id="userCard" tabIndex="-1" role="dialog" style={{marginTop: 20 + 'px', marginBottom: 20 + 'px'}}>
            <div className="card-header">
              <div className="float-right">
                <div className="dropdown">
                  <button className="btn btn-secondary dropdown-toggle" type="button" id="dropdownLang" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                    <i className="fas fa-globe-africa"></i>
                  </button>
                  <div className="dropdown-menu" aria-labelledby="dropdownLang">
                    {langList}
                  </div>
                </div>
              </div>
              <h2>{i18next.t("glewlwyd-sso-title")}</h2>
            </div>
            <div className="card-body">
              {body}
            </div>
            <div className="card-footer">
              <Buttons config={this.state.config} currentUser={this.state.currentUser} userList={this.state.userList} showGrant={this.state.showGrant} showGrantAsterisk={this.state.showGrantAsterisk} newUser={this.state.newUser} newUserScheme={this.state.newUserScheme}/>
            </div>
          </div>
          <Notification/>
        </div>
      );
    } else {
      return (
        <div aria-live="polite" aria-atomic="true" style={{position: "relative", minHeight: "200px"}}>
          <div className="card center" id="userCard" tabIndex="-1" role="dialog" style={{marginTop: 20 + 'px', marginBottom: 20 + 'px'}}>
            <div className="card-header">
              <h4>
                <span className="badge badge-danger">
                  {i18next.t("error-api-connect")}
                </span>
              </h4>
            </div>
          </div>
        </div>
      );
    }
	}
}

export default App;
