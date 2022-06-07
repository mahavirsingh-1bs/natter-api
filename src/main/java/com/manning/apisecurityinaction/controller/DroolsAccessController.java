package com.manning.apisecurityinaction.controller;

import java.util.HashMap;
import java.util.Map;

import org.kie.api.KieServices;
import org.kie.api.runtime.KieContainer;

public class DroolsAccessController extends ABACAccessController {
	
	private final KieContainer kieContainer;

    public DroolsAccessController() {
        this.kieContainer = KieServices.get().getKieClasspathContainer();
    }
    
	@Override
	Decision checkPermitted(Map<String, Object> subject, 
							Map<String, Object> resource, 
							Map<String, Object> action,
							Map<String, Object> env) {
		var session = kieContainer.newKieSession();
        try {
            var decision = new Decision();
            session.setGlobal("decision", decision);

            session.insert(new Subject(subject));
            session.insert(new Resource(resource));
            session.insert(new Action(action));
            session.insert(new Environment(env));

            session.fireAllRules();
            return decision;

        } finally {
            session.dispose();
        }
	}
	
	@SuppressWarnings("serial")
	public static class Subject extends HashMap<String, Object> {
        Subject(Map<String, Object> m) { super(m); }
    }

	@SuppressWarnings("serial")
	public static class Resource extends HashMap<String, Object> {
        Resource(Map<String, Object> m) { super(m); }
    }

	@SuppressWarnings("serial")
	public static class Action extends HashMap<String, Object> {
        Action(Map<String, Object> m) { super(m); }
    }

	@SuppressWarnings("serial")
	public static class Environment extends HashMap<String, Object> {
        Environment(Map<String, Object> m) { super(m); }
    }

}
