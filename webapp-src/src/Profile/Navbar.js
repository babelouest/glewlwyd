import React, { Component } from 'react';
import i18next from 'i18next';

import messageDispatcher from '../lib/MessageDispatcher';
import apiManager from '../lib/APIManager';

class Navbar extends Component {
  constructor(props) {
    super(props);

    this.state = {
      config: props.config,
      curNav: "profile",
      loggedIn: props.loggedIn,
      schemeList: props.schemeList,
      profileList: props.profileList,
      dataHighlight: props.dataHighlight,
      schemeHighlight: props.schemeHighlight,
      registering: props.registering
    }

    this.navigate = this.navigate.bind(this);
    this.toggleLogin = this.toggleLogin.bind(this);
    this.changeLang = this.changeLang.bind(this);
    this.changeProfile = this.changeProfile.bind(this);
    
    messageDispatcher.subscribe('Nav', (message) => {
      if (message.type === "profile") {
        this.navigate(false, "profile", null);
      } else {
        this.navigate(false, message.page, message.type);
      }
    });
  }

  componentWillReceiveProps(nextProps) {
    this.setState({
      loggedIn: nextProps.loggedIn, 
      schemeList: nextProps.schemeList,
      profileList: nextProps.profileList,
      dataHighlight: nextProps.dataHighlight,
      schemeHighlight: nextProps.schemeHighlight,
      registering: nextProps.registering
    });
  }
  
  navigate(e, page, type) {
    if (e) {
      e.preventDefault();
    }
    messageDispatcher.sendMessage('App', {type: "nav", page: page, module: type});
    this.setState({curNav: page});
  }

  toggleLogin() {
    if (this.state.loggedIn) {
      apiManager.glewlwydRequest("/auth/?username=" + encodeURIComponent(this.state.profileList[0].username), "DELETE")
      .then(() => {
        messageDispatcher.sendMessage('Notification', {type: "info", message: i18next.t("login.success-delete-session")});
        messageDispatcher.sendMessage('App', {type: 'loggedIn', loggedIn: false});
      })
      .fail((err) => {
        if (err.status !== 401) {
          messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.error-delete-session")});
        }
        messageDispatcher.sendMessage('App', {type: 'loggedIn', loggedIn: false});
      });
    } else {
      var schemeDefault = false;
      this.state.config.sessionSchemes.forEach((scheme) => {
        if (scheme.scheme_default) {
          scheme.scheme_default.forEach((page) => {
            if (page === "profile") {
              schemeDefault = scheme.scheme_name;
            }
          });
        }
      });
      document.location.href = this.state.config.LoginUrl + "?callback_url=" + encodeURIComponent([location.protocol, '//', location.host, location.pathname].join('')) + "&scope=" + encodeURIComponent(this.state.config.profile_scope) + (schemeDefault?("&scheme="+encodeURIComponent(schemeDefault)):"");
    }
  }

  changeLang(e, lang) {
    i18next.changeLanguage(lang)
    .then(() => {
      this.setState({lang: lang});
      messageDispatcher.sendMessage('App', {type: "lang"});
    });
  }
  
  changeProfile(e, profile) {
    if (profile) {
      apiManager.glewlwydRequest("/auth/", "POST", {username: profile.username})
      .then(() => {
        messageDispatcher.sendMessage('App', {type: "profile"});
      })
      .fail(() => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.error-login")});
      });
    } else {
      var schemeDefault = false;
      this.state.config.sessionSchemes.forEach((scheme) => {
        if (scheme.scheme_default) {
          scheme.scheme_default.forEach((page) => {
            if (page === "admin") {
              schemeDefault = scheme.scheme_name;
            }
          });
        }
      });
      document.location.href = this.state.config.LoginUrl + "?callback_url=" + encodeURIComponent([location.protocol, '//', location.host, location.pathname].join('')) + "&scope=" + encodeURIComponent(this.state.config.profile_scope) + (schemeDefault?("&scheme="+encodeURIComponent(schemeDefault)):"");
    }
  }

	render() {
    var langList = [], schemeList = [], profileList = [], dataHighlight = "", completeAlert = "", complete = true;
    var profileDropdown, logoutButton;
    var passwordJsx, sessionJsx, profileJsx;
    this.state.config.lang.forEach((lang, i) => {
      if (lang === i18next.language) {
        langList.push(<a className="dropdown-item active" href="#" key={i}>{lang}</a>);
      } else {
        langList.push(<a className="dropdown-item" href="#" onClick={(e) => this.changeLang(e, lang)} key={i}>{lang}</a>);
      }
    });
    this.state.schemeList.forEach((scheme, index) => {
      var highlight = "";
      if (this.state.schemeHighlight[scheme.name]) {
        complete = false;
        highlight = " required-field";;
      }
      if (scheme.module !== "retype-password" && scheme.module !== "email") { // Because schemes retype-password and e-mail code have no user configuration
        schemeList.push(
          <li className={"nav-item" + (this.state.curNav===scheme.name?" active":"")} key={index}>
            <a className={"nav-link"+highlight} href="#" onClick={(e) => this.navigate(e, scheme.name, scheme.module)}>{scheme.display_name||scheme.name}</a>
          </li>
        );
      }
    });
    if (!this.state.config.params.delegate && !this.state.config.params.register) {
      passwordJsx = <li className={"nav-item" + (this.state.curNav==="password"?" active":"")}>
        <a className="nav-link" href="#" onClick={(e) => this.navigate(e, "password", null)}>{i18next.t("profile.menu-password")}</a>
      </li>
    }
    if (this.state.profileList && !this.state.config.params.register) {
      sessionJsx = <li className={"nav-item" + (this.state.curNav==="session"?" active":"")}>
        <a className="nav-link" href="#" onClick={(e) => this.navigate(e, "session", null)}>{i18next.t("profile.menu-session")}</a>
      </li>
    }
    if (this.state.profileList) {
      this.state.profileList.forEach((profile, index) => {
        profileList.push(<a className={"dropdown-item"+(!index?" active":"")} href="#" onClick={(e) => this.changeProfile(e, profile)} key={index}>{profile.name||profile.username}</a>);
      });
    }
    profileList.push(<div className="dropdown-divider" key={profileList.length}></div>);
    profileList.push(<a className="dropdown-item" href="#" onClick={(e) => this.changeProfile(e, null)} key={profileList.length}>{i18next.t("profile.menu-session-new")}</a>);
    if (!this.state.config.params.register) {
      profileDropdown = 
      <div className="btn-group" role="group">
        <button className="btn btn-secondary dropdown-toggle" type="button" id="dropdownProfile" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
          <i className="fas fa-user"></i>
        </button>
        <div className="dropdown-menu" aria-labelledby="dropdownProfile">
          {profileList}
        </div>
      </div>;
      logoutButton = 
        <button type="button" className="btn btn-secondary" onClick={this.toggleLogin} title={i18next.t((this.state.loggedIn?"title-logout":"title-login"))}>
          <i className="fas fa-sign-in-alt btn-icon"></i>
        </button>;
    } else if (this.state.dataHighlight) {
      complete = false;
      dataHighlight = " required-field";
    }
    if (this.state.registering) {
      if (complete) {
        completeAlert =
          <li className="nav-item" >
            <a className="btn btn-success" href="#" onClick={(e) => this.navigate(e, "profile", null)}>
              {i18next.t("profile.register-profile-nav-complete")}
            </a>
          </li>
      } else {
        completeAlert =
          <li className="nav-item" >
            <a className="btn btn-danger" href="#" onClick={(e) => this.navigate(e, "profile", null)}>
              {i18next.t("profile.register-profile-nav-incomplete")}
            </a>
          </li>
      }
    }
		return (
      <nav className="navbar navbar-expand-lg navbar-light bg-light">
        <a className="navbar-brand" href="#">
          <img className="mr-3" src="img/logo-profile.png" alt="logo"/>
          {i18next.t("profile.menu-title")}
        </a>
        <button className="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarSupportedContent" aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="Toggle navigation">
          <span className="navbar-toggler-icon"></span>
        </button>
        <div className="collapse navbar-collapse" id="navbarSupportedContent">
          <ul className="navbar-nav mr-auto">
            <li className={"nav-item" + (this.state.curNav==="profile"?" active":"")}>
              <a className={"nav-link"+dataHighlight} href="#" onClick={(e) => this.navigate(e, "profile", null)}>{i18next.t("profile.menu-user")}</a>
            </li>
            {sessionJsx}
            {passwordJsx}
            {schemeList}
            {completeAlert}
          </ul>
          <div className="btn-group" role="group">
            <div className="btn-group" role="group">
              <button className="btn btn-secondary dropdown-toggle" type="button" id="dropdownLang" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                <i className="fas fa-globe-africa"></i>
              </button>
              <div className="dropdown-menu" aria-labelledby="dropdownLang">
                {langList}
              </div>
            </div>
            {profileDropdown}
            {logoutButton}
          </div>
        </div>
      </nav>
		);
	}
}

export default Navbar;
